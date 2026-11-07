// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestInterceptOutcomeResponseFlushBeforeReceipt checks delivery while outcome storage is blocked.
func TestInterceptOutcomeResponseFlushBeforeReceipt(t *testing.T) {
	for _, surface := range []string{"buffered", "exempt", "sse"} {
		for _, fail := range []bool{false, true} {
			t.Run(surface+"/"+map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
				cache, pool, cfg, _, logger, m := testInterceptSetup(t)
				cfg.FlightRecorder.RequireReceipts = true
				cfg.ResponseScanning.Enabled = true
				if surface == "exempt" {
					cfg.ResponseScanning.ExemptDomains = []string{testLoopbackIP}
				}
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				pub, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
				if err != nil {
					t.Fatal(err)
				}
				rph := &receiptProxyHelper{dir: dir, rec: rec, priv: key, pubHex: hex.EncodeToString(pub)}
				t.Cleanup(func() { _ = rph.rec.Close() })
				storage := &blockingOutcomeRecorder{rec: rph.rec, entered: make(chan struct{}), release: make(chan struct{}), fail: fail}
				var once sync.Once
				release := func() { once.Do(func() { close(storage.release) }) }
				defer release()
				shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
					Recorder: rph.rec, PrivKey: rph.priv, ConfigHash: coverageTestConfigHash,
					Principal: "local", Actor: "pipelock", Metrics: m,
				}, "proxy", 2, 0)
				if err != nil {
					t.Fatal(err)
				}
				opening, _ := shards.Opening()
				v2 := make([]*proxydecision.Emitter, len(opening.Shards))
				for i, shard := range opening.Shards {
					v2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{
						Recorder: storage, Signer: proxydecision.NewKeyedSigner(rph.priv),
						Principal: "local", Actor: "pipelock", Session: shard.SessionID,
					})
				}
				var failures atomic.Int32
				option, err := WithReceiptShardSet(shards, v2, func(error) { failures.Add(1) })
				if err != nil {
					t.Fatal(err)
				}
				p, err := New(cfg, logger, sc, m, option)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				payload, contentType := "ordinary response", "text/plain"
				if surface == "sse" {
					payload, contentType = "data: ok\n\n", "text/event-stream"
				}
				rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					header := http.Header{"Content-Type": {contentType}}
					if surface != "buffered" {
						// Streaming retains the upstream framing; no length is
						// synthesized by the intercept handler.
						header.Set("Content-Length", strconv.Itoa(len(payload)))
					}
					return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
				})
				clientConn, proxyConn := net.Pipe()
				t.Cleanup(func() { _ = clientConn.Close() })
				tlsConn := tls.Client(clientConn, &tls.Config{RootCAs: pool, ServerName: testLoopbackIP})
				t.Cleanup(func() { _ = tlsConn.Close() })
				done := make(chan error, 1)
				go func() {
					done <- interceptTunnel(t.Context(), proxyConn, &InterceptContext{
						Config: cfg, Scanner: sc, Logger: logger, Metrics: m, CertCache: cache,
						TargetHost: testLoopbackIP, TargetPort: "443", Proxy: p, UpstreamRT: rt,
					})
				}()
				t.Cleanup(release)
				if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testLoopbackIP+"/data", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Close = true
				if err := req.Write(tlsConn); err != nil {
					t.Fatal(err)
				}
				received := make(chan error, 1)
				go func() {
					resp, readErr := http.ReadResponse(bufio.NewReader(tlsConn), req)
					if readErr == nil {
						defer func() { _ = resp.Body.Close() }()
						if resp.StatusCode != http.StatusOK || resp.ContentLength != int64(len(payload)) || len(resp.TransferEncoding) != 0 {
							readErr = errors.New("response missing exact framing or success status")
						} else {
							var body []byte
							body, readErr = io.ReadAll(resp.Body)
							if readErr == nil && string(body) != payload {
								readErr = errors.New("unexpected response body: " + string(body))
							}
						}
					}
					received <- readErr
				}()
				select {
				case <-storage.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("outcome emitter did not enter storage")
				}
				select {
				case err := <-received:
					if err != nil {
						t.Fatalf("response not delivered while outcome storage blocked: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("response buffered behind outcome storage")
				}
				if failures.Load() != 0 {
					t.Fatal("group failed before outcome storage returned")
				}
				select {
				case err := <-done:
					t.Fatalf("tunnel ended before storage release: %v", err)
				default:
				}
				release()
				_ = clientConn.Close()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("tunnel did not finish after outcome release")
				}
				wantFailures := int32(0)
				if fail {
					wantFailures = 1
				}
				if failures.Load() != wantFailures {
					t.Fatalf("group failure callbacks = %d, want %d", failures.Load(), wantFailures)
				}
				for i, shard := range shards.Emitters() {
					if (shard.HealthError() != nil) != fail {
						t.Fatalf("shard %d health = %v, fail = %v", i, shard.HealthError(), fail)
					}
				}
				if err := rph.rec.Close(); err != nil {
					t.Fatal(err)
				}
				paths, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				var receipts []receipt.Receipt
				for _, path := range paths {
					entries, err := recorder.ReadEntries(path)
					if err != nil {
						t.Fatal(err)
					}
					for _, entry := range entries {
						if entry.Type != "action_receipt" {
							continue
						}
						rcpt, err := receipt.Unmarshal(entry.RawDetail)
						if err != nil {
							t.Fatal(err)
						}
						if err := receipt.VerifyWithKey(rcpt, rph.pubHex); err != nil {
							t.Fatal(err)
						}
						receipts = append(receipts, rcpt)
					}
				}
				var pair []receipt.Receipt
				for _, rcpt := range receipts {
					if rcpt.ActionRecord.Transport == "intercept" && rcpt.ActionRecord.Layer != receiptEmissionFailedLayer {
						pair = append(pair, rcpt)
					}
				}
				if len(pair) != 2 {
					t.Fatalf("intent/outcome count = %d, want 2", len(pair))
				}
				if fail {
					marker := requireReceiptEmissionFailedLayer(t, receipts)
					if marker.ActionRecord.Pattern != "outcome receipt emission failed" {
						t.Fatalf("failure marker = %+v", marker.ActionRecord)
					}
				}
				pattern := receiptOutcomePattern("200", int64(len(payload)), "complete")
				if surface == "sse" {
					pattern = receiptOutcomePattern("200", -1, "sse_stream")
				}
				if pair[1].ActionRecord.Pattern != pattern {
					t.Fatalf("outcome = %q, want %q", pair[1].ActionRecord.Pattern, pattern)
				}
				want := pair[0].ActionRecord
				want.Timestamp, want.DecisionPhase, want.Layer, want.Pattern = pair[1].ActionRecord.Timestamp, receipt.DecisionPhaseOutcome, receiptOutcomeLayer, pattern
				want.ChainSeq++
				want.ChainPrevHash, err = receipt.ReceiptHash(pair[0])
				if err != nil {
					t.Fatal(err)
				}
				wantReceipt, err := receipt.Sign(want, rph.priv)
				if err != nil {
					t.Fatal(err)
				}
				gotJSON, err := json.Marshal(pair[1])
				if err != nil {
					t.Fatal(err)
				}
				wantJSON, err := json.Marshal(wantReceipt)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(gotJSON, wantJSON) {
					t.Fatalf("outcome bytes changed:\n%s\n%s", gotJSON, wantJSON)
				}
			})
		}
	}
}

// TestInterceptBufferedOutcomeFraming checks exact lengths and bodyless response exclusions.
func TestInterceptBufferedOutcomeFraming(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		method               string
		status               int
		body                 string
		required, wantLength bool
		strip                bool
	}{
		{"plain", http.MethodGet, http.StatusOK, "ok", true, true, false},
		{"empty", http.MethodGet, http.StatusOK, "", true, true, false},
		{"stripped", http.MethodGet, http.StatusOK, testInjectionPayload, true, true, true},
		{"head", http.MethodHead, http.StatusOK, "", true, false, false},
		{"informational", http.MethodGet, http.StatusEarlyHints, "", true, false, false},
		{"no_content", http.MethodGet, http.StatusNoContent, "", true, false, false},
		{"not_modified", http.MethodGet, http.StatusNotModified, "", true, false, false},
		{"receipts_off", http.MethodGet, http.StatusOK, "ok", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, cfg, _, logger, m := testInterceptSetup(t)
			cfg.FlightRecorder.RequireReceipts = tc.required
			if tc.strip {
				cfg.ResponseScanning.Action = config.ActionStrip
			}
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			rph := newReceiptProxyHelper(t)
			t.Cleanup(func() { _ = rph.rec.Close() })
			p, err := New(cfg, logger, sc, m, WithReceiptEmitter(rph.emitter))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			handler := newInterceptHandler(&InterceptContext{Config: cfg, Scanner: sc, Logger: logger, Metrics: m, TargetHost: testLoopbackIP, TargetPort: "443", Proxy: p}, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"text/plain"}, "Transfer-Encoding": {"chunked"}}, Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
			}))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), tc.method, "https://"+testLoopbackIP+"/data", nil))
			if tc.status == http.StatusNotModified {
				baseline := httptest.NewRecorder()
				writeFullResponseBlock(baseline, "")
				if w.Code != baseline.Code || w.Body.String() != baseline.Body.String() || w.Header().Get("Content-Length") != baseline.Header().Get("Content-Length") {
					t.Fatal("304 refusal changed")
				}
				return
			}
			if got := w.Header().Get("Content-Length"); tc.wantLength && got != strconv.Itoa(w.Body.Len()) || !tc.wantLength && got != "" {
				t.Fatalf("Content-Length = %q, body length = %d", got, w.Body.Len())
			}
			if got := w.Header().Get("Transfer-Encoding"); got != "" {
				t.Fatalf("Transfer-Encoding = %q", got)
			}
			if tc.strip && (!strings.Contains(w.Body.String(), "[REDACTED") || strings.Contains(w.Body.String(), testInjectionPayload)) {
				t.Fatalf("expected stripped representation, got %q", w.Body.String())
			}
			if w.Flushed != tc.required {
				t.Fatalf("flushed = %v, required = %v", w.Flushed, tc.required)
			}
		})
	}
}

// TestInterceptOutcomeFlushDeliveryError checks receipts after a client disconnects during the final flush.
func TestInterceptOutcomeFlushDeliveryError(t *testing.T) {
	runOutcomeFlushFailure(t, "intercept", true, 0)
}

// TestInterceptOutcomeFlushStalledClient checks that a stalled client cannot prevent outcome recording.
func TestInterceptOutcomeFlushStalledClient(t *testing.T) {
	runOutcomeFlushFailure(t, "intercept", false, 0)
}

// TestInterceptOutcomeFlushPreservesServerWriteDeadline checks that the existing server deadline stays in force.
func TestInterceptOutcomeFlushPreservesServerWriteDeadline(t *testing.T) {
	runOutcomeFlushFailure(t, "intercept", false, 100*time.Millisecond)
}

// TestInterceptTunnelOutcomeFlushStalledClient checks bounded delivery on the inner TLS HTTP server.
func TestInterceptTunnelOutcomeFlushStalledClient(t *testing.T) {
	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.FlightRecorder.RequireReceipts = true
	cfg.ForwardProxy.IdleTimeoutSeconds = 1
	cfg.ResponseScanning.Enabled = true
	sc := scanner.MustNew(cfg)
	rph := newReceiptProxyHelper(t)
	t.Cleanup(func() { _ = rph.rec.Close() })
	observed := make(chan receipt.ActionRecord, 1)
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rph.rec, PrivKey: rph.priv, ConfigHash: coverageTestConfigHash,
		Principal: coverageTestPrincipal, Actor: coverageTestActor,
		OnReceipt: func(rcpt *receipt.Receipt) {
			if rcpt.ActionRecord.DecisionPhase == receipt.DecisionPhaseOutcome {
				observed <- rcpt.ActionRecord
			}
		},
	})
	p, err := New(cfg, logger, sc, m, WithReceiptEmitter(emitter))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	tlsClient := tls.Client(client, &tls.Config{RootCAs: pool, ServerName: testLoopbackIP})
	done := make(chan error, 1)
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat("ordinary response ", 64))), Request: r}, nil
	})
	go func() {
		done <- interceptTunnel(t.Context(), server, &InterceptContext{
			Config: cfg, Scanner: sc, Logger: logger, Metrics: m, CertCache: cache,
			TargetHost: testLoopbackIP, TargetPort: "443", Proxy: p, UpstreamRT: rt,
		})
	}()
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("tunnel exit: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("tunnel did not exit")
		}
	})
	if err := tlsClient.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testLoopbackIP+"/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Close = true
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	// After the TLS handshake and request, the client never reads a response.
	select {
	case ar := <-observed:
		if ar.Verdict != config.ActionAllow || ar.Pattern != "status=200 bytes=unknown reason=incomplete" {
			t.Fatalf("stalled tunnel outcome = %+v", ar)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("inner HTTP flush prevented outcome storage")
	}
}

// TestInterceptOutcomeSyntheticResponseBeforeReceipt checks diagnostic delivery before outcome storage.
func TestInterceptOutcomeSyntheticResponseBeforeReceipt(t *testing.T) {
	for _, condition := range []string{"upstream_error", "blocked"} {
		t.Run(condition, func(t *testing.T) { testOutcomeSyntheticResponseBeforeReceipt(t, "intercept", condition) })
	}
}
