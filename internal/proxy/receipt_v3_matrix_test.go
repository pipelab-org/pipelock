// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type v3SyncFaultFile struct {
	*os.File
	syncs int
}

func (f *v3SyncFaultFile) Sync() error {
	f.syncs++
	if f.syncs == 2 {
		return errors.New("flush failed")
	}
	return f.File.Sync()
}

// The opening file flush succeeds. The first append to that file fails to
// flush, and the writer can publish a successor using the normal filesystem.
func v3FirstAppendSyncFault() func(string, string) (v3.StreamFile, error) {
	first := true
	return func(dir, pattern string) (v3.StreamFile, error) {
		file, err := os.CreateTemp(dir, pattern)
		if err != nil || !first {
			return file, err
		}
		first = false
		return &v3SyncFaultFile{File: file}, nil
	}
}

func newTestV3HTTPProxy(t *testing.T, surface string, required bool, createTemp func(string, string) (v3.StreamFile, error), configure ...func(*v3.StreamWriterOptions)) (*Proxy, *v3.StreamWriter, string, []ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	keySeed := sha256.Sum256([]byte("receipt transport fixture"))
	key := ed25519.NewKeyFromSeed(keySeed[:])
	keys := []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}
	cfg := testScannerConfig()
	cfg.Internal = nil
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.MaxTunnelSeconds = 10
	cfg.ForwardProxy.IdleTimeoutSeconds = 2
	cfg.WebSocketProxy.Enabled = true
	cfg.WebSocketProxy.MaxConnectionSeconds = 10
	cfg.WebSocketProxy.IdleTimeoutSeconds = 2
	cfg.ResponseScanning.Enabled = false
	writerOpts := v3.StreamWriterOptions{
		Dir: dir, SigningKey: key, PolicyHash: v3.Digest(nil), CreateTempFile: createTemp,
		Identity: v3.Writer{Instance: "example", Product: "Pipelock", Version: "3"},
		Coverage: v3.Coverage{
			ReceiptsRequired: required, Surfaces: []string{surface},
			RedactionRuleset: v3.Ruleset{ID: "example", Version: "1", Hash: v3.Digest(nil)},
		},
	}
	for _, apply := range configure {
		apply(&writerOpts)
	}
	writer, err := v3.OpenStreamWriter(t.Context(), writerOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = writer.Close(ctx, nil)
	})
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithV3ReceiptWriter(writer))
	if err != nil {
		t.Fatal(err)
	}
	return p, writer, dir, keys
}

func TestV3HTTPTransportParity(t *testing.T) {
	for _, surface := range []string{TransportFetch, TransportForward, TransportConnect, transportInterceptReceipt, TransportReverse, TransportWS} {
		for _, required := range []bool{false, true} {
			for _, tc := range []struct {
				name     string
				fault    func(string, string) (v3.StreamFile, error)
				released bool
			}{
				{name: "ok", released: true},
				{name: "intent flush failure", fault: v3FirstAppendSyncFault()},
			} {
				t.Run(fmt.Sprintf("%s/required=%t/%s", surface, required, tc.name), func(t *testing.T) {
					p, writer, dir, keys := newTestV3HTTPProxy(t, surface, required, tc.fault)
					var reached, intentVisible atomic.Int64
					observe := func() {
						reached.Add(1)
						result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
						if err == nil && result.Integrity == "ok" && result.Counts.EffectsUnknown != nil && *result.Counts.EffectsUnknown > 0 {
							intentVisible.Add(1)
						}
					}
					status := exerciseV3Transport(t, p, surface, observe)
					if tc.released {
						want := http.StatusOK
						if surface == TransportWS {
							want = http.StatusSwitchingProtocols
						}
						if status != want || reached.Load() != 1 || intentVisible.Load() != 1 {
							t.Fatalf("status=%d upstream hits=%d with prior intent=%d, want %d/1/1", status, reached.Load(), intentVisible.Load(), want)
						}
					} else if status != http.StatusForbidden || reached.Load() != 0 {
						t.Fatalf("failed intent released an effect: status=%d upstream hits=%d", status, reached.Load())
					}
					if err := writer.Close(t.Context(), nil); err != nil {
						t.Fatal(err)
					}
					result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
					if err != nil || result.Integrity != "ok" {
						t.Fatalf("receipt verification: %+v (%v)", result, err)
					}
					if tc.released && result.Verdict != "VALID" {
						t.Fatalf("verdict=%s findings=%v", result.Verdict, result.Findings)
					}
				})
			}
		}
	}
}

func exerciseV3Transport(t *testing.T, p *Proxy, surface string, observe func()) int {
	t.Helper()
	if surface == TransportConnect {
		return exerciseV3Connect(t, p, observe)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observe()
		if surface == TransportWS {
			conn, _, _, err := ws.UpgradeHTTP(r, w)
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set(headerContentType, "text/plain")
		_, _ = io.WriteString(w, "example")
	}))
	t.Cleanup(upstream.Close)
	response := httptest.NewRecorder()
	switch surface {
	case TransportFetch:
		p.handleFetch(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil))
	case TransportForward:
		p.handleForwardHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil))
	case TransportReverse:
		target, err := url.Parse(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		reverse := NewReverseProxy(target, p.ConfigPtr(), p.ScannerPtr(), audit.NewNop(), metrics.New(), nil, nil, nil)
		reverse.SetOwnerProxy(p)
		reverse.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	case TransportWS:
		done := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(done)
			p.handleWebSocket(w, r)
		}))
		t.Cleanup(server.Close)
		reply := requestWSHandshake(t, strings.TrimPrefix(server.URL, "http://"), strings.TrimPrefix(upstream.URL, "http://"), nil)
		_ = reply.Body.Close()
		waitForV3Transport(t, done)
		return reply.StatusCode
	case transportInterceptReceipt:
		cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			out := req.Clone(req.Context())
			target, err := url.Parse(upstream.URL)
			if err != nil {
				return nil, err
			}
			out.URL.Scheme, out.URL.Host = target.Scheme, target.Host
			return upstream.Client().Transport.RoundTrip(out)
		})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testLoopbackIP+"/example", nil)
		reply := interceptWithRT(t, cache, pool, cfg, sc, logger, m, rt,
			&InterceptContext{Proxy: p, TargetHost: testLoopbackIP, TargetPort: "443"}, req)
		defer func() { _ = reply.Body.Close() }()
		if _, err := io.Copy(io.Discard, reply.Body); err != nil {
			t.Fatal(err)
		}
		return reply.StatusCode
	default:
		t.Fatalf("unknown surface %q", surface)
	}
	return response.Result().StatusCode
}

func exerciseV3Connect(t *testing.T, p *Proxy, observe func()) int {
	t.Helper()
	target, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		conn, err := target.Accept()
		if err == nil {
			defer func() { _ = conn.Close() }()
			observe()
		}
	}()
	t.Cleanup(func() {
		_ = target.Close()
		waitForV3Transport(t, accepted)
	})
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		p.handleConnect(w, r)
	}))
	t.Cleanup(server.Close)
	conn := dialProxy(t, strings.TrimPrefix(server.URL, "http://"))
	addr := target.Addr().String()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr); err != nil {
		t.Fatal(err)
	}
	reply, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = reply.Body.Close()
	waitForV3Transport(t, done)
	_ = target.Close()
	waitForV3Transport(t, accepted)
	return reply.StatusCode
}

func waitForV3Transport(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("transport did not settle")
	}
}
