// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestNativeCapacityHTTPAdmission(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportForward, TransportReverse, "intercept"} {
		t.Run(transport, func(t *testing.T) {
			p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			releaseUpstream := sync.OnceFunc(func() { close(release) })
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				select {
				case <-release:
					_, _ = io.WriteString(w, "completed")
				case <-r.Context().Done():
				}
			}))
			defer upstream.Close()
			defer releaseUpstream()
			dst, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			dst.Host = "api.vendor.example:" + dst.Port()
			handler := p.Handler()
			target := dst.String()
			switch transport {
			case TransportFetch:
				target = "/fetch?url=" + url.QueryEscape(target)
			case TransportReverse:
				rp := NewReverseProxy(dst, p.ConfigPtr(), p.ScannerPtr(), p.logger, p.metrics, p.ks, nil, nil)
				rp.SetOwnerProxy(p)
				rp.SetSafeDialer(p.SafeDialer())
				rp.SetReceiptEmitter(p.ReceiptEmitterPtr())
				handler = rp
				target = "/"
			case "intercept":
				intercept := &InterceptContext{
					TargetHost: dst.Hostname(), TargetPort: dst.Port(), Config: p.CurrentConfig(),
					Scanner: p.ScannerPtr().Load(), Logger: p.logger, Metrics: p.metrics, Proxy: p,
				}
				handler = newInterceptHandler(intercept, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					out := req.Clone(req.Context())
					out.URL.Scheme = "http"
					out.URL.Host = strings.TrimPrefix(upstream.URL, "http://")
					return upstream.Client().Transport.RoundTrip(out)
				}))
			}
			request := func() *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil))
				return w
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- request() }()
			select {
			case <-entered:
			case early := <-done:
				t.Fatalf("admitted request ended before upstream effect: %d %s", early.Code, early.Body.String())
			case <-ctx.Done():
				t.Fatal("admitted request did not reach upstream")
			}
			refused := request()
			if refused.Code != http.StatusServiceUnavailable || !strings.Contains(refused.Body.String(), ael.ErrCapacity.Error()) {
				t.Fatalf("second request = %d %s", refused.Code, refused.Body.String())
			}
			select {
			case <-entered:
				t.Fatal("refused request reached upstream")
			default:
			}
			releaseUpstream()
			select {
			case got := <-done:
				if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "completed") {
					t.Fatalf("first request = %d %s", got.Code, got.Body.String())
				}
			case <-ctx.Done():
				t.Fatal("first request did not finish")
			}
			verifyNativeCapacityClose(t, e, dir)
		})
	}
}

func newNativeCapacityProxy(t *testing.T, slots int64) (*Proxy, *receipt.Emitter, string) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"127.0.0.1"}}
	cfg.TrustedDomains = []string{"api.vendor.example"}
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	cfg.ForwardProxy.Enabled = true
	cfg.WebSocketProxy.Enabled = true
	cfg.FlightRecorder.RequireReceipts = true
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	slot := ael.ActivityRecordLimit(len(receipt.ActionUnclassified), 36)
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key, Session: session, ConfigHash: coverageTestConfigHash, NativeCapacity: ael.NewCapacity(slots*slot + 2048)})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithRecorder(rec), WithReceiptEmitter(e), WithSession(session))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p, e, dir
}

func verifyNativeCapacityClose(t *testing.T, e *receipt.Emitter, dir string) {
	t.Helper()
	select {
	case <-e.NativeCapacity().Drained():
	default:
		t.Fatal("native capacity leases still outstanding")
	}
	if err := e.EmitSessionClose("graceful_shutdown"); err != nil && !errors.Is(err, receipt.ErrChainSealed) {
		t.Fatal(err)
	}
	runs, err := filepath.Glob(filepath.Join(dir, "ael", "*"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("native evidence paths %v, error %v", runs, err)
	}
	if _, err := ael.VerifyRun(dir, filepath.Base(runs[0]), e.SignerKeyHex()); err != nil {
		t.Fatalf("verify native close: %v", err)
	}
}

func TestNativeCapacityClosesWebSocket(t *testing.T) {
	p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+2*nativeWSMessageRecords+4)
	upstreamAddr, closeUpstream := wsEchoServer(t)
	defer closeUpstream()
	_, port, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(p.Handler())
	defer proxyServer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	target := "ws://api.vendor.example:" + port + "/"
	conn, _, _, err := (ws.Dialer{}).Dial(ctx, "ws"+strings.TrimPrefix(proxyServer.URL, "http")+"/ws?url="+url.QueryEscape(target))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	payload := []byte("fixture message")
	if err := wsutil.WriteClientMessage(conn, ws.OpText, payload); err != nil {
		t.Fatal(err)
	}
	got, _, err := wsutil.ReadServerData(conn)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("upstream echo = %q, %v", got, err)
	}
	assertCapacityRefusesFetch(t, p, ctx)
	_, _, err = wsutil.ReadServerData(conn)
	var closed wsutil.ClosedError
	if !errors.As(err, &closed) || closed.Code != ws.StatusGoingAway || closed.Reason != nativeCapacityStopReason {
		t.Fatalf("WebSocket terminal frame = %v", err)
	}
	waitCapacityDrain(t, ctx, e)
	verifyNativeCapacityClose(t, e, dir)
	verifyNativeStreamOutcome(t, e, dir, TransportWS)
}

func TestNativeCapacityClosesConnectTunnel(t *testing.T) {
	p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	upstream := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			upstream <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_, err = io.Copy(conn, conn)
		upstream <- err
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(p.Handler())
	defer server.Close()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	target := "api.vendor.example:" + port
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %v, %v", resp, err)
	}
	defer func() { _ = resp.Body.Close() }()
	const payload = "tunnel message"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != payload {
		t.Fatalf("upstream echo = %q, %v", got, err)
	}
	assertCapacityRefusesFetch(t, p, ctx)
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected CONNECT client socket to close, got %v", err)
	}
	select {
	case err := <-upstream:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("CONNECT upstream was not closed")
	}
	waitCapacityDrain(t, ctx, e)
	verifyNativeCapacityClose(t, e, dir)
	verifyNativeStreamOutcome(t, e, dir, TransportConnect)
}

func assertCapacityRefusesFetch(t *testing.T, p *Proxy, ctx context.Context) {
	t.Helper()
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "/fetch?url=https://api.vendor.example/", nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), ael.ErrCapacity.Error()) {
		t.Fatalf("capacity refusal = %d %s", w.Code, w.Body.String())
	}
}

func waitCapacityDrain(t *testing.T, ctx context.Context, e *receipt.Emitter) {
	t.Helper()
	select {
	case <-e.NativeCapacity().Drained():
	case <-ctx.Done():
		t.Fatal("capacity did not drain")
	}
}

func verifyNativeStreamOutcome(t *testing.T, e *receipt.Emitter, dir, transport string) {
	t.Helper()
	result, err := recorder.QuerySession(dir, e.Session(), &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.Entries {
		signed, err := receipt.Unmarshal(entry.RawDetail)
		if err != nil {
			t.Fatal(err)
		}
		record := signed.ActionRecord
		if record.Transport != transport || record.DecisionPhase != receipt.DecisionPhaseOutcome ||
			!strings.Contains(record.Pattern, nativeCapacityStopReason) {
			continue
		}
		if err := receipt.VerifyWithKey(signed, e.SignerKeyHex()); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("missing signed %s capacity outcome", transport)
}

func TestNativeCapacityClosesHTTPSSE(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportReverse, "intercept"} {
		t.Run(transport, func(t *testing.T) {
			p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			upstreamClosed := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"message\":\"fixture\"}\n\n")
				if err := http.NewResponseController(w).Flush(); err != nil {
					return
				}
				<-r.Context().Done()
				close(upstreamClosed)
			}))
			defer upstream.Close()
			defer cancel()
			dst, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			dst.Host = "api.vendor.example:" + dst.Port()
			handler := p.Handler()
			switch transport {
			case TransportReverse:
				rp := NewReverseProxy(dst, p.ConfigPtr(), p.ScannerPtr(), p.logger, p.metrics, p.ks, nil, nil)
				rp.SetOwnerProxy(p)
				rp.SetSafeDialer(p.SafeDialer())
				rp.SetReceiptEmitter(p.ReceiptEmitterPtr())
				handler = rp
			case "intercept":
				intercept := &InterceptContext{
					TargetHost: dst.Hostname(), TargetPort: dst.Port(), Config: p.CurrentConfig(),
					Scanner: p.ScannerPtr().Load(), Logger: p.logger, Metrics: p.metrics, Proxy: p,
				}
				handler = newInterceptHandler(intercept, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					out := req.Clone(req.Context())
					out.URL.Scheme = "http"
					out.URL.Host = strings.TrimPrefix(upstream.URL, "http://")
					return upstream.Client().Transport.RoundTrip(out)
				}))
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			defer cancel()
			client := server.Client()
			target := server.URL + "/"
			if transport == TransportForward {
				proxyURL, err := url.Parse(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				rt := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
				defer rt.CloseIdleConnections()
				client = &http.Client{Transport: rt}
				target = dst.String()
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if transport == "intercept" {
				request.Host = dst.Host
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			reader := bufio.NewReader(response.Body)
			if event, err := reader.ReadString('\n'); err != nil || response.StatusCode != http.StatusOK || !strings.Contains(event, "fixture") {
				t.Fatalf("first SSE event: status=%d event=%q err=%v", response.StatusCode, event, err)
			}
			assertCapacityRefusesFetch(t, p, ctx)
			select {
			case <-upstreamClosed:
			case <-ctx.Done():
				t.Fatal("capacity did not close upstream SSE")
			}
			if rest, _ := io.ReadAll(reader); strings.Contains(string(rest), "data:") {
				t.Fatalf("unexpected event after capacity: %q", rest)
			}
			waitCapacityDrain(t, ctx, e)
			verifyNativeCapacityClose(t, e, dir)
			verifyNativeStreamOutcome(t, e, dir, transport)
		})
	}
}
