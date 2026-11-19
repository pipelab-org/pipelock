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
	"sync/atomic"
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

func TestNativeCapacityReservesEachCredentialAudienceAllow(t *testing.T) {
	const (
		host       = "api.vendor.example"
		allowCount = nativeRequestRecords + 1
	)
	for _, tc := range []struct {
		name       string
		slots      int64
		wantStatus int
		wantAllows int
	}{
		{"admitted", nativeRequestRecords + allowCount, http.StatusOK, allowCount},
		{"refused", nativeRequestRecords + allowCount - 4, http.StatusServiceUnavailable, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, emitter, dir := newNativeCapacityProxy(t, tc.slots, func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = false
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
				cfg.RequestBodyScanning.SensitiveHeaders = []string{headerNameAuthorization}
				for i := range allowCount {
					pattern := audienceReceiptTestPattern(host)
					pattern.Name = fmt.Sprintf("Test audience %03d", i)
					cfg.DLP.Patterns = append(cfg.DLP.Patterns, pattern)
				}
			})
			var hits atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				_, _ = io.WriteString(w, "ok")
			}))
			defer upstream.Close()

			endpoint, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			target := *endpoint
			target.Host = net.JoinHostPort(host, target.Port())
			p.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				out := req.Clone(req.Context())
				out.URL.Host = endpoint.Host
				return upstream.Client().Transport.RoundTrip(out)
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(target.String()), nil)
			req.Header.Set(headerNameAuthorization, "Bearer "+audienceReceiptTestCredential)
			res := httptest.NewRecorder()
			p.handleFetch(res, req)
			if res.Code != tc.wantStatus {
				t.Fatalf("fetch status = %d, want %d, response %s", res.Code, tc.wantStatus, res.Body)
			}
			if tc.wantStatus == http.StatusServiceUnavailable {
				if !strings.Contains(res.Body.String(), ael.ErrCapacity.Error()) || hits.Load() != 0 {
					t.Fatalf("capacity refusal: body %s and %d upstream hits", res.Body, hits.Load())
				}
			} else {
				if hits.Load() != 1 {
					t.Fatalf("upstream hits = %d, want 1", hits.Load())
				}
				if _, err := emitter.ReserveNativeRecords(int(tc.slots)); !errors.Is(err, ael.ErrCapacity) {
					t.Fatalf("force the next admission to stop: %v", err)
				}
			}
			verifyNativeCapacityClose(t, emitter, dir)
			rows, err := recorder.QuerySession(dir, emitter.Session(), &recorder.QueryFilter{Type: "action_receipt"})
			if err != nil {
				t.Fatal(err)
			}
			patterns := make(map[string]struct{})
			var signedCount int
			for _, row := range rows.Entries {
				signed, err := receipt.Unmarshal(row.RawDetail)
				if err != nil {
					t.Fatal(err)
				}
				if signed.ActionRecord.Layer != credentialAudienceReceiptExtensionKey {
					continue
				}
				if err := receipt.VerifyWithKey(signed, emitter.SignerKeyHex()); err != nil {
					t.Fatal(err)
				}
				signedCount++
				patterns[signed.ActionRecord.Pattern] = struct{}{}
			}
			if signedCount != tc.wantAllows || len(patterns) != tc.wantAllows {
				t.Fatalf("signed allows = %d, distinct patterns = %d, want %d", signedCount, len(patterns), tc.wantAllows)
			}
			t.Logf("HTTP %d, upstream hits %d, verified individual allows %d", res.Code, hits.Load(), signedCount)
		})
	}
}

func TestNativeCapacityRefusesAuthorizationAtProxyBoundaries(t *testing.T) {
	const (
		host          = "api.vendor.example"
		intercepted   = "intercept"
		headerCarrier = "header"
		urlCarrier    = "url"
		bodyCarrier   = "body"
	)
	var hits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	endpoint, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination := *endpoint
	destination.Host = net.JoinHostPort(host, endpoint.Port())

	for _, tc := range []struct{ transport, carrier string }{
		{TransportConnect, headerCarrier},
		{TransportFetch, urlCarrier},
		{TransportForward, headerCarrier},
		{TransportForward, urlCarrier},
		{TransportForward, bodyCarrier},
		{TransportReverse, headerCarrier},
		{TransportReverse, urlCarrier},
		{TransportReverse, bodyCarrier},
		{intercepted, headerCarrier},
		{intercepted, urlCarrier},
		{intercepted, bodyCarrier},
		{TransportWS, headerCarrier},
		{TransportWS, urlCarrier},
	} {
		t.Run(tc.transport+"/"+tc.carrier, func(t *testing.T) {
			p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
				cfg.RequestBodyScanning.SensitiveHeaders = []string{headerNameAuthorization}
				for i := range 16 {
					pattern := audienceReceiptTestPattern(host)
					pattern.Name = fmt.Sprintf("Test gateway %02d", i)
					cfg.DLP.Patterns = append(cfg.DLP.Patterns, pattern)
				}
			})
			outbound := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				out := req.Clone(req.Context())
				out.URL.Host = endpoint.Host
				return upstream.Client().Transport.RoundTrip(out)
			})
			p.client.Transport = outbound
			target := destination
			method := http.MethodGet
			var body io.Reader
			switch tc.carrier {
			case urlCarrier:
				target.RawQuery = url.Values{"fixture": []string{audienceReceiptTestCredential}}.Encode()
			case bodyCarrier:
				method = http.MethodPost
				body = strings.NewReader(fmt.Sprintf(`{"fixture":%q}`, audienceReceiptTestCredential))
			}

			var handler http.Handler = http.HandlerFunc(p.handleForwardHTTP)
			requestURL := target.String()
			switch tc.transport {
			case TransportConnect:
				handler = http.HandlerFunc(p.handleConnect)
				method = http.MethodConnect
				requestURL = target.Host
			case TransportFetch:
				handler = http.HandlerFunc(p.handleFetch)
				requestURL = "/fetch?url=" + url.QueryEscape(target.String())
			case TransportReverse:
				rp := NewReverseProxy(&destination, p.ConfigPtr(), p.ScannerPtr(), p.logger, p.metrics, p.ks, nil, nil)
				rp.SetOwnerProxy(p)
				rp.SetReceiptEmitter(p.ReceiptEmitterPtr())
				rp.SetSafeDialer(p.SafeDialer())
				handler = rp
				requestURL = "/"
				if target.RawQuery != "" {
					requestURL += "?" + target.RawQuery
				}
			case intercepted:
				ic := &InterceptContext{
					TargetHost: target.Hostname(), TargetPort: target.Port(), Config: p.CurrentConfig(),
					Scanner: p.ScannerPtr().Load(), Logger: p.logger, Metrics: p.metrics, Proxy: p,
				}
				handler = newInterceptHandler(ic, outbound)
			case TransportWS:
				handler = http.HandlerFunc(p.handleWebSocket)
				target.Scheme = "wss"
				requestURL = "/ws?url=" + url.QueryEscape(target.String())
			}
			req := httptest.NewRequestWithContext(t.Context(), method, requestURL, body)
			if tc.carrier == headerCarrier {
				req.Header.Set(headerNameAuthorization, "Bearer "+audienceReceiptTestCredential)
			}
			if tc.carrier == bodyCarrier {
				req.Header.Set("Content-Type", "application/json")
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusServiceUnavailable || !strings.Contains(res.Body.String(), ael.ErrCapacity.Error()) {
				t.Fatalf("capacity refusal = %d %s", res.Code, res.Body)
			}
			if hits.Load() != 0 {
				t.Fatalf("refused work reached upstream %d times", hits.Load())
			}
			verifyNativeCapacityClose(t, e, dir)
		})
	}
}

func TestNativeCapacityRefusesUnreservableIssuerCookieBatch(t *testing.T) {
	p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4)
	admission, err := p.reserveReceiptAdmission()
	if err != nil {
		t.Fatal(err)
	}
	defer admission.ReleaseNativeAdmission()
	ic := &InterceptContext{Proxy: p, Config: p.CurrentConfig(), receiptShard: admission}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/", nil)
	allowance := issuerCookieAllowance{Name: "fixture", Patterns: make([]string, nativeRequestRecords)}
	for i := range allowance.Patterns {
		allowance.Patterns[i] = "fixture"
	}
	if err := ic.recordIssuerCookieAllows(audit.NewRequestLogContext("fixture"), req, req.URL.String(), []issuerCookieAllowance{allowance}); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("issuer-cookie batch admission = %v", err)
	}
	admission.ReleaseNativeAdmission()
	verifyNativeCapacityClose(t, e, dir)
}

func newNativeCapacityProxy(t *testing.T, slots int64, configure ...func(*config.Config)) (*Proxy, *receipt.Emitter, string) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"127.0.0.1"}}
	cfg.TrustedDomains = []string{"api.vendor.example"}
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	cfg.ForwardProxy.Enabled = true
	cfg.WebSocketProxy.Enabled = true
	cfg.FlightRecorder.RequireReceipts = true
	for _, apply := range configure {
		apply(cfg)
	}
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
	for _, required := range []bool{true, false} {
		t.Run(nativeReceiptModeName(required), func(t *testing.T) {
			testNativeCapacityClosesWebSocket(t, required)
		})
	}
}

func testNativeCapacityClosesWebSocket(t *testing.T, required bool) {
	t.Helper()
	p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+2*nativeWSMessageRecords+4, func(cfg *config.Config) { cfg.FlightRecorder.RequireReceipts = required })
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
	verifyNativeStreamOutcome(t, e, dir, TransportWS, required)
}

func TestNativeCapacityRefusesUnreservedWebSocketMessages(t *testing.T) {
	for _, direction := range []string{"client", "upstream"} {
		t.Run(direction, func(t *testing.T) {
			p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			begin := make(chan struct{})
			upResult := make(chan error, 1)
			payload := []byte("fixture message")
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				up, _, _, err := ws.UpgradeHTTP(r, w)
				if err != nil {
					upResult <- err
					return
				}
				defer func() { _ = up.Close() }()
				if direction == "upstream" {
					select {
					case <-begin:
					case <-ctx.Done():
						return
					}
					if err := wsutil.WriteServerMessage(up, ws.OpText, payload); err != nil {
						upResult <- err
						return
					}
				}
				_, _, err = wsutil.ReadClientData(up)
				upResult <- err
			}))
			defer upstream.Close()
			defer cancel()
			_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(p.Handler())
			defer server.Close()
			target := "ws://api.vendor.example:" + port + "/"
			conn, _, _, err := (ws.Dialer{}).Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/ws?url="+url.QueryEscape(target))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			deadline, _ := ctx.Deadline()
			if err := conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			close(begin)
			if direction == "client" {
				if err := wsutil.WriteClientMessage(conn, ws.OpText, payload); err != nil {
					t.Fatal(err)
				}
			}
			_, _, err = wsutil.ReadServerData(conn)
			var closed wsutil.ClosedError
			if !errors.As(err, &closed) || closed.Code != ws.StatusGoingAway || closed.Reason != nativeCapacityStopReason {
				t.Fatalf("message refusal = %v", err)
			}
			select {
			case err := <-upResult:
				if !errors.As(err, &closed) {
					t.Fatalf("upstream received data or missed the close: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("upstream did not settle")
			}
			waitCapacityDrain(t, ctx, e)
			verifyNativeCapacityClose(t, e, dir)
			verifyNativeStreamOutcome(t, e, dir, TransportWS, true)
		})
	}
}

func TestNativeCapacityClosesConnectTunnel(t *testing.T) {
	for _, required := range []bool{true, false} {
		t.Run(nativeReceiptModeName(required), func(t *testing.T) {
			testNativeCapacityClosesConnectTunnel(t, required)
		})
	}
}

func testNativeCapacityClosesConnectTunnel(t *testing.T, required bool) {
	t.Helper()
	p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4, func(cfg *config.Config) { cfg.FlightRecorder.RequireReceipts = required })
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
	verifyNativeStreamOutcome(t, e, dir, TransportConnect, required)
}

func assertCapacityRefusesFetch(t *testing.T, p *Proxy, ctx context.Context) {
	t.Helper()
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "/fetch?url=https://api.vendor.example/", nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), ael.ErrCapacity.Error()) {
		t.Fatalf("capacity refusal = %d %s", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		method  string
		target  string
		handler http.HandlerFunc
	}{
		{http.MethodConnect, "api.vendor.example:443", p.handleConnect},
		{http.MethodGet, "/ws?url=wss://api.vendor.example/", p.handleWebSocket},
	} {
		res := httptest.NewRecorder()
		tc.handler(res, httptest.NewRequestWithContext(ctx, tc.method, tc.target, nil))
		if res.Code != http.StatusServiceUnavailable || !strings.Contains(res.Body.String(), ael.ErrCapacity.Error()) {
			t.Fatalf("%s %s capacity refusal = %d %s", tc.method, tc.target, res.Code, res.Body.String())
		}
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

func verifyNativeStreamOutcome(t *testing.T, e *receipt.Emitter, dir, transport string, required bool) {
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
		if record.Transport != transport || !strings.Contains(record.Pattern, nativeCapacityStopReason) {
			continue
		}
		if required && record.DecisionPhase != receipt.DecisionPhaseOutcome {
			continue
		}
		if !required && (record.DecisionPhase != "" || record.Layer != nativeStreamCloseLayer || record.Verdict != config.ActionWarn) {
			continue
		}
		if err := receipt.VerifyWithKey(signed, e.SignerKeyHex()); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("missing signed %s capacity outcome", transport)
}

func nativeReceiptModeName(required bool) string {
	if required {
		return "required"
	}
	return "best_effort"
}

func TestNativeCapacityClosesHTTPSSE(t *testing.T) {
	const intercepted = "intercept"
	for _, tc := range []struct {
		transport string
		required  bool
	}{
		{TransportForward, true},
		{TransportForward, false},
		{TransportReverse, true},
		{TransportReverse, false},
		{intercepted, true},
		{intercepted, false},
	} {
		transport := tc.transport
		t.Run(transport+"/"+nativeReceiptModeName(tc.required), func(t *testing.T) {
			p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4, func(cfg *config.Config) { cfg.FlightRecorder.RequireReceipts = tc.required })
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
			verifyNativeStreamOutcome(t, e, dir, transport, tc.required)
		})
	}
}
