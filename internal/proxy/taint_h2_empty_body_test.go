// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

func TestSettleUnknownLengthBody(t *testing.T) {
	errRead := errors.New("stream reset")
	newReq := func(method string, proto int, body io.Reader) *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), method, "https://api.vendor.example/items", body)
		r.ProtoMajor = proto
		r.ContentLength = -1
		return r
	}
	t.Run("untouched", func(t *testing.T) {
		h1 := newReq(http.MethodGet, 1, io.NopCloser(strings.NewReader("")))
		post := newReq(http.MethodPost, 2, io.NopCloser(strings.NewReader("")))
		trailer := newReq(http.MethodGet, 2, io.NopCloser(strings.NewReader("")))
		trailer.Trailer = http.Header{"X-Exfil": nil}
		chunked := newReq(http.MethodGet, 2, io.NopCloser(strings.NewReader("")))
		chunked.TransferEncoding = []string{"chunked"}
		known := newReq(http.MethodGet, 2, strings.NewReader("abc"))
		known.ContentLength = 3
		noBody := newReq(http.MethodGet, 2, http.NoBody)
		for name, r := range map[string]*http.Request{"http1": h1, "post": post, "declared_trailer": trailer, "chunked": chunked, "known_length": known, "no_body": noBody} {
			if got := settleUnknownLengthBody(r, time.Second); got != r {
				t.Errorf("%s: request was rewritten", name)
			}
		}
		if settleUnknownLengthBody(nil, time.Second) != nil {
			t.Error("nil request was rewritten")
		}
	})
	for _, tc := range []struct {
		name     string
		method   string
		body     func() (io.ReadCloser, func())
		wait     time.Duration
		wantBody bool
		wantData string
		wantErr  error
	}{
		{name: "empty_get", method: http.MethodGet, body: func() (io.ReadCloser, func()) { return io.NopCloser(strings.NewReader("")), nil }, wait: time.Second},
		{name: "empty_lowercase_head", method: "head", body: func() (io.ReadCloser, func()) { return io.NopCloser(strings.NewReader("")), nil }, wait: time.Second},
		{name: "empty_options", method: http.MethodOptions, body: func() (io.ReadCloser, func()) { return io.NopCloser(strings.NewReader("")), nil }, wait: time.Second},
		{name: "empty_trace", method: http.MethodTrace, body: func() (io.ReadCloser, func()) { return io.NopCloser(strings.NewReader("")), nil }, wait: time.Second},
		{name: "data_get", method: http.MethodGet, body: func() (io.ReadCloser, func()) { return io.NopCloser(strings.NewReader("payload")), nil }, wait: time.Second, wantBody: true, wantData: "payload"},
		{name: "data_with_eof", method: http.MethodGet, body: func() (io.ReadCloser, func()) { return io.NopCloser(iotest.DataErrReader(strings.NewReader("x"))), nil }, wait: time.Second, wantBody: true, wantData: "x"},
		{name: "read_error", method: http.MethodGet, body: func() (io.ReadCloser, func()) { return io.NopCloser(iotest.ErrReader(errRead)), nil }, wait: time.Second, wantBody: true, wantErr: errRead},
		{name: "stalled_then_data", method: http.MethodGet, body: func() (io.ReadCloser, func()) {
			pr, pw := io.Pipe()
			return pr, func() { _, _ = io.WriteString(pw, "late"); _ = pw.Close() }
		}, wait: 10 * time.Millisecond, wantBody: true, wantData: "late"},
		{name: "stalled_then_empty", method: http.MethodGet, body: func() (io.ReadCloser, func()) {
			pr, pw := io.Pipe()
			return pr, func() { _ = pw.Close() }
		}, wait: 10 * time.Millisecond, wantBody: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, after := tc.body()
			r := newReq(tc.method, 2, body)
			r.Body = body
			got := settleUnknownLengthBody(r, tc.wait)
			if got == r {
				t.Fatal("eligible request was not settled")
			}
			if r.ContentLength != -1 || r.Body != body {
				t.Fatal("settle modified the caller's request")
			}
			if has := requestHasBody(got); has != tc.wantBody {
				t.Fatalf("requestHasBody=%v want %v", has, tc.wantBody)
			}
			if !tc.wantBody {
				if got.Body != http.NoBody || got.ContentLength != 0 {
					t.Fatalf("empty body not settled: body=%T length=%d", got.Body, got.ContentLength)
				}
				return
			}
			if after != nil {
				go after()
			}
			data, err := io.ReadAll(got.Body)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("read err=%v want %v", err, tc.wantErr)
			}
			if string(data) != tc.wantData {
				t.Fatalf("replayed body=%q want %q", data, tc.wantData)
			}
			if err := got.Body.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
		})
	}
}

// h2EmptyBodyGET sends a GET whose body has unknown length. With an empty
// body the HTTP/2 transport sends HEADERS without END_STREAM and then an empty
// DATA frame with END_STREAM.
func h2EmptyBodyGET(t *testing.T, srv *httptest.Server, host, body string) (proto, status int) {
	t.Helper()
	client := srv.Client()
	client.Transport.(*http.Transport).ForceAttemptHTTP2 = true
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/items", io.NopCloser(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.ProtoMajor, resp.StatusCode
}

// shapeRecorder proves each request reached the handler as HTTP/2 with an
// unknown length, the shape the settle step resolves.
func shapeRecorder(next http.Handler, sawShape *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && r.ContentLength == -1 && r.Body != nil && r.Body != http.NoBody {
			sawShape.Add(1)
		}
		next.ServeHTTP(w, r)
	})
}

// After untrusted exposure, an HTTP/2 GET that ends its stream with an empty
// DATA frame is a bodyless read, and proceeds on the TLS-intercepted and reverse
// paths. A GET that sends data the same way stays refused like POST.
func TestTaintEmptyUnknownLengthHTTP2Body(t *testing.T) {
	t.Run("intercept", func(t *testing.T) {
		// With request body scanning on, the drained zero-length body is
		// re-evaluated and admitted; the early classification decides alone
		// only with it off.
		p, _, rec, target, ic := newTaintInterceptFixture(t, func(cfg *config.Config) {
			cfg.RequestBodyScanning.Enabled = false
		})
		observeHTTPResponseTaint(rec, p.CurrentConfig(), target, "text/plain", "forward_response", false)
		var upstreamCalls atomic.Int32
		handler := newInterceptHandler(ic, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			upstreamCalls.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
		}))
		var sawShape atomic.Int32
		parsed, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		host := parsed.Host
		srv := httptest.NewUnstartedServer(shapeRecorder(handler, &sawShape))
		srv.EnableHTTP2 = true
		srv.StartTLS()
		t.Cleanup(srv.Close)

		if proto, status := h2EmptyBodyGET(t, srv, host, ""); proto != 2 || status != http.StatusOK || upstreamCalls.Load() != 1 {
			t.Fatalf("empty h2 GET proto=%d status=%d calls=%d, want 2/200/1", proto, status, upstreamCalls.Load())
		}
		if _, status := h2EmptyBodyGET(t, srv, host, "notes from the session"); status != http.StatusForbidden || upstreamCalls.Load() != 1 {
			t.Fatalf("bodied h2 GET status=%d calls=%d, want 403 with no upstream call", status, upstreamCalls.Load())
		}
		if got := sawShape.Load(); got != 2 {
			t.Fatalf("requests with unknown-length HTTP/2 shape=%d, want 2", got)
		}
	})

	t.Run("reverse", func(t *testing.T) {
		cfg := reverseParityBaseConfig(t)
		cfg.CrossRequestDetection.Enabled = false
		cfg.SessionProfiling.Enabled = true
		cfg.Taint.Enabled = true
		cfg.Taint.Policy = config.ModeBalanced
		cfg.RequestBodyScanning.Enabled = false
		var upstreamHits atomic.Int32
		rp, p, _ := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
			upstreamHits.Add(1)
			w.WriteHeader(http.StatusOK)
		})
		rec := p.SessionMgrPtr().Load().GetOrCreate(responseTaintSessionKey(cfg, "", "127.0.0.1", envelope.ActorAuthSelfDeclared))
		observeHTTPResponseTaint(rec, cfg, "https://untrusted.vendor.example/page", "text/html", "forward_response", false)
		var sawShape atomic.Int32
		host := ""
		srv := httptest.NewUnstartedServer(shapeRecorder(rp, &sawShape))
		srv.EnableHTTP2 = true
		srv.StartTLS()
		t.Cleanup(srv.Close)

		if proto, status := h2EmptyBodyGET(t, srv, host, ""); proto != 2 || status != http.StatusOK || upstreamHits.Load() != 1 {
			t.Fatalf("empty h2 reverse GET proto=%d status=%d hits=%d, want 2/200/1", proto, status, upstreamHits.Load())
		}
		if _, status := h2EmptyBodyGET(t, srv, host, "payload"); status != http.StatusForbidden || upstreamHits.Load() != 1 {
			t.Fatalf("bodied h2 reverse GET status=%d hits=%d, want 403 with no upstream hit", status, upstreamHits.Load())
		}
		if got := sawShape.Load(); got != 2 {
			t.Fatalf("requests with unknown-length HTTP/2 shape=%d, want 2", got)
		}
	})
}
