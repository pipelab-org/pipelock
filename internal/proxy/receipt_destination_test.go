// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/configs"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestReceiptDestinationContent(t *testing.T) {
	for _, preset := range []string{"observe", "audit", "balanced"} {
		for _, transport := range []string{TransportFetch, TransportForward} {
			t.Run(preset+"/"+transport, func(t *testing.T) {
				cfg := config.Defaults()
				if preset == "observe" {
					enforce := false
					cfg.Enforce = &enforce
				} else {
					data, ok := configs.Preset(preset)
					if !ok {
						t.Fatal("missing preset")
					}
					var err error
					cfg, err = config.LoadPolicyBundleBytes(data)
					if err != nil {
						t.Fatal(err)
					}
				}
				cfg.Internal = nil
				cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
				cfg.ForwardProxy.Enabled = true
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				secret := strings.Join([]string{"receipt", "private", "credential"}, "-")
				if !sc.ScanTextForDLP(t.Context(), secret).Clean {
					t.Fatal("credential fixture is already recognized by DLP")
				}
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write([]byte("destination response"))
				}))
				defer upstream.Close()
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, Redact: true}, sc.ScanTextForDLP, priv)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = rec.Close() })
				v1 := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, Principal: "local", Actor: "pipelock"})
				if err := v1.EmitSessionOpen(); err != nil {
					t.Fatal(err)
				}
				signer := proxydecision.NewKeyedSigner(priv)
				v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
					Recorder: rec, Signer: signer, Principal: "local", Actor: "pipelock",
					Sanitize: proxydecision.SanitizeFromRedactor(rec.ReceiptRedactor()),
				})
				p, err := New(cfg, audit.NewNop(), sc, metrics.New(),
					WithRecorder(rec), WithReceiptEmitter(v1), WithV2ReceiptEmitter(v2))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				handler := p.buildHandler(p.buildMux())
				for _, component := range []string{"userinfo", "path", "query", "fragment"} {
					target, parseErr := url.Parse(upstream.URL + "/")
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					switch component {
					case "userinfo":
						target.User = url.UserPassword("user", secret)
					case "path":
						target.Path = "/" + secret
					case "query":
						target.RawQuery = "key=" + secret
					case "fragment":
						target.Fragment = secret
					}
					requestTarget := target.String()
					if transport == TransportFetch {
						requestTarget = "/fetch?url=" + url.QueryEscape(requestTarget)
					}
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestTarget, nil)
					if transport == TransportForward {
						req.URL = target
					}
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusOK {
						t.Fatalf("%s status=%d body=%s", component, w.Code, w.Body.String())
					}
				}
				if err := v1.EmitSessionClose("shutdown"); err != nil {
					t.Fatal(err)
				}
				if err := rec.Close(); err != nil {
					t.Fatal(err)
				}
				entries := readAllEntries(t, dir)
				var actions []receipt.Receipt
				for _, entry := range entries {
					raw, marshalErr := json.Marshal(entry)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					if strings.Contains(string(raw), secret) {
						t.Fatalf("raw credential retained in signed evidence: %s", raw)
					}
					if entry.Type != receiptEntryType {
						continue
					}
					detail, marshalErr := json.Marshal(entry.Detail)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					r, unmarshalErr := receipt.Unmarshal(detail)
					if unmarshalErr != nil {
						t.Fatal(unmarshalErr)
					}
					if r.ActionRecord.SessionControl == nil {
						ar := r.ActionRecord
						if ar.Target != upstream.URL || ar.Verdict != config.ActionAllow ||
							ar.Method != http.MethodGet || ar.Transport != transport || ar.RequestID == "" {
							t.Fatalf("lost decision correlation: %+v", ar)
						}
					}
					actions = append(actions, r)
				}
				if len(actions) < 6 {
					t.Fatalf("missing v1 receipts: %d", len(actions))
				}
				pin := hex.EncodeToString(pub)
				if result := receipt.VerifyChain(actions, pin); !result.Valid {
					t.Fatalf("v1 chain: %+v", result)
				}
				evidence, err := contractreceipt.ExtractEvidenceReceiptsFromEntries(entries)
				if err != nil || len(evidence) < 4 {
					t.Fatalf("v2 receipts=%d error=%v", len(evidence), err)
				}
				if result := receipt.VerifyEvidenceChainTrusted(evidence, []string{pin}, contractreceipt.ChainVerifyOptions{}); !result.Valid {
					t.Fatalf("v2 chain: %+v", result)
				}
				for _, r := range evidence {
					var payload contractreceipt.PayloadProxyDecisionStruct
					if err := json.Unmarshal(r.Payload, &payload); err != nil {
						t.Fatal(err)
					}
					if payload.Target != upstream.URL || payload.Transport != transport || payload.Verdict != config.ActionAllow || len(payload.PolicySources) == 0 {
						t.Fatalf("v2 lost destination: %+v", payload)
					}
				}
			})
		}
	}
}
