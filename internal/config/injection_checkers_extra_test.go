// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A cloned checker definition shares no pointer with its source, so a
// snapshot cannot change when the live config is edited.
func TestInjectionCheckerCloneIsDeep(t *testing.T) {
	uid := uint32(1000)
	allow, consent := true, true
	lo, hi, threshold := 0.0, 1.0, 0.5
	src := InjectionCheckerConfig{
		PeerUID: &uid, AllowLoopbackHTTP: &allow, SendContentOffHost: &consent, Threshold: &threshold,
		Revision: &InjectionCheckerRevision{Checker: "c", Model: "m", Adapter: "a"},
		Score:    &InjectionCheckerScore{Scale: "s", Min: &lo, Max: &hi},
	}
	before := src.canonicalString()
	out := src.clone()
	*out.PeerUID, *out.AllowLoopbackHTTP, *out.SendContentOffHost, *out.Threshold = 0, false, false, 0.9
	out.Revision.Model = "changed"
	out.Score.Scale = "changed"
	*out.Score.Min, *out.Score.Max = -1, 2
	if src.canonicalString() != before {
		t.Fatal("mutating a clone changed its source")
	}
	if got := cloneInjectionCheckers(nil); got != nil {
		t.Fatalf("clone of nil = %v", got)
	}
	// A score with open bounds clones without inventing them.
	open := InjectionCheckerConfig{Score: &InjectionCheckerScore{Scale: "s"}}.clone()
	if open.Score.Min != nil || open.Score.Max != nil {
		t.Fatal("clone invented score bounds")
	}
}

func TestInjectionCheckerEndpointDiagnostics(t *testing.T) {
	bad := InjectionCheckerConfig{Type: InjectionCheckerTypeProtocol, Endpoint: "http://[::1"}
	if !bad.SendsOffHost() {
		t.Fatal("unparseable endpoint treated as on-host")
	}
	if bad.EndpointHost() != "invalid" {
		t.Fatalf("EndpointHost = %q", bad.EndpointHost())
	}
	for endpoint, offHost := range map[string]bool{
		"http://127.0.0.1:9000/check":          false,
		"http://[::1]:9000/check":              false,
		"http://localhost:9000/check":          true, // a name can resolve anywhere
		"https://checker.vendor.example/check": true,
	} {
		c := InjectionCheckerConfig{Type: InjectionCheckerTypeProtocol, Endpoint: endpoint}
		if c.SendsOffHost() != offHost {
			t.Errorf("%s: SendsOffHost = %v, want %v", endpoint, c.SendsOffHost(), offHost)
		}
	}
	jev := InjectionCheckerConfig{Type: InjectionCheckerTypeJev, APIKeyEnv: "JEV_KEY", AuthorizationEnv: "IGNORED"}
	if jev.CredentialEnv() != "JEV_KEY" || jev.EffectiveEndpoint() != JevDefaultEndpoint {
		t.Fatalf("jev credential/endpoint = %q %q", jev.CredentialEnv(), jev.EffectiveEndpoint())
	}
}

func TestValidateInjectionCheckersWithoutSection(t *testing.T) {
	cfg := Defaults()
	cfg.PromptInjectionDetection = nil
	if err := cfg.validateInjectionCheckers(); err != nil {
		t.Fatal(err)
	}
}

func writeTestCA(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "checker test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCheckerCAPool(t *testing.T) {
	dir := t.TempDir()
	if pool, err := LoadCheckerCAPool(writeTestCA(t, dir)); err != nil || pool == nil {
		t.Fatalf("valid CA: pool=%v err=%v", pool, err)
	}
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	huge := filepath.Join(dir, "huge.pem")
	if err := os.WriteFile(huge, []byte(strings.Repeat("A", maxCheckerCAFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing":   filepath.Join(dir, "missing.pem"),
		"directory": dir,
		"too large": huge,
		"no PEM":    notPEM,
	} {
		if _, err := LoadCheckerCAPool(path); err == nil {
			t.Errorf("%s: CA file accepted", name)
		}
	}
}
