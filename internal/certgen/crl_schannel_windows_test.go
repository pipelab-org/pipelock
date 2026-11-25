// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package certgen

import (
	"crypto/tls"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const schannelTestBody = "schannel ok"

// TestWindowsSchannelUsesCRLDistributionPoint runs the built-in Schannel curl,
// which checks revocation by default, against an interception leaf. Without a
// distribution point Schannel cannot determine revocation status and refuses
// the connection; with one it fetches the signed CRL and accepts it.
func TestWindowsSchannelUsesCRLDistributionPoint(t *testing.T) {
	// Select the built-in client even if Git's OpenSSL curl precedes it on PATH.
	curl := filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe")
	version, err := exec.CommandContext(t.Context(), curl, "--version").CombinedOutput() // #nosec G204 G702 -- the Windows-only test runs the built-in curl under SystemRoot.
	if err != nil || !strings.Contains(strings.ToLower(string(version)), "schannel") {
		t.Fatalf("native Schannel curl unavailable: %v: %s", err, version)
	}
	for _, tc := range []struct {
		name           string
		distribution   bool
		wantAcceptance bool
	}{
		{name: "without distribution point", distribution: false, wantAcceptance: false},
		{name: "with distribution point", distribution: true, wantAcceptance: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, key, _, err := GenerateCA("Pipelock Schannel Test", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			cache, err := NewCertCache(ca, key, time.Hour, 8)
			if err != nil {
				t.Fatal(err)
			}
			crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				der, err := cache.CRL()
				if err != nil {
					http.Error(w, err.Error(), http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/pkix-crl")
				_, _ = w.Write(der)
			}))
			t.Cleanup(crlServer.Close)
			if tc.distribution {
				cache.SetCRLDistributionPoints([]string{crlServer.URL + "/ca.crl"})
			}
			leaf, err := cache.Get("127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, schannelTestBody)
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			t.Cleanup(server.Close)
			caPath := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.CommandContext(t.Context(), curl, "--silent", "--show-error", "--fail", "--max-time", "15", "--noproxy", "*", "--cacert", caPath, server.URL).CombinedOutput() // #nosec G204 G702 -- the Windows-only test runs the built-in curl under SystemRoot.
			accepted := err == nil && string(output) == schannelTestBody
			if accepted != tc.wantAcceptance {
				t.Fatalf("Schannel accepted=%v, want %v: %v: %s", accepted, tc.wantAcceptance, err, output)
			}
			if !tc.wantAcceptance && !strings.Contains(strings.ToLower(string(output)), "revocation") {
				t.Fatalf("Schannel refused for a reason other than revocation: %v: %s", err, output)
			}
		})
	}
}
