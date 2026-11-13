// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func enableRequestRedaction(cfg *config.Config) {
	cfg.Redaction = redact.Config{
		Enabled:        true,
		DefaultProfile: "code",
		Profiles: map[string]redact.ProfileSpec{
			"code": {Classes: []string{string(redact.ClassAWSAccessKey)}},
		},
		Limits: redact.DefaultLimits(),
	}
}

func gzipRequestBody(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if len(plain) > 0 {
		if _, err := w.Write(plain); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func deflateRequestBody(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if len(plain) > 0 {
		if _, err := w.Write(plain); err != nil {
			t.Fatalf("deflate write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("deflate close: %v", err)
	}
	return buf.Bytes()
}

func rawDeflateRequestBody(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

type codedUpstream struct {
	hits atomic.Int32
	body []byte
	enc  string
	clen int64
}

func (u *codedUpstream) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		u.body = append([]byte(nil), body...)
		u.enc = r.Header.Get("Content-Encoding")
		u.clen = r.ContentLength
		w.WriteHeader(http.StatusNoContent)
	}
}

func forwardCodedRequest(t *testing.T, cfgMod func(*config.Config), body []byte, encodings []string, contentType string) (int, string, http.Header, *codedUpstream) {
	t.Helper()
	up := &codedUpstream{}
	backend := httptest.NewServer(up.handler())
	t.Cleanup(backend.Close)

	proxyAddr, p, cleanup := setupForwardProxyWithLogger(t, nil, cfgMod)
	t.Cleanup(cleanup)
	installForwardTestDialer(p, backend.Listener.Addr().String())

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.example.com/v1/upload", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if contentType == "" {
		contentType = "text/plain"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Del("Content-Encoding")
	for _, encoding := range encodings {
		req.Header.Add("Content-Encoding", encoding)
	}
	resp, err := forwardHTTPClient(t, proxyAddr).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody), resp.Header, up
}

func TestForwardCodedBodyMatchesIdentityFindings(t *testing.T) {
	secret := fakeAPIKey()
	injection := testInjectionPayload
	cases := []struct {
		name    string
		plain   string
		coding  string
		wrap    func(*testing.T, []byte) []byte
		wantDLP bool
	}{
		{name: "identity credential", plain: secret, wantDLP: true},
		{name: "gzip credential", plain: secret, coding: "gzip", wrap: gzipRequestBody, wantDLP: true},
		{name: "deflate credential", plain: secret, coding: "deflate", wrap: deflateRequestBody, wantDLP: true},
		{name: "identity injection", plain: injection},
		{name: "gzip injection", plain: injection, coding: "gzip", wrap: gzipRequestBody},
		{name: "deflate injection", plain: injection, coding: "deflate", wrap: deflateRequestBody},
	}
	type observed struct {
		status  int
		reason  string
		layer   string
		audit   string
		receipt string
	}
	saw := map[string]observed{}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(tt.plain)
			var encodings []string
			if tt.wrap != nil {
				body = tt.wrap(t, body)
				encodings = []string{tt.coding}
			}
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			rph := newReceiptProxyHelper(t)
			up := &codedUpstream{}
			backend := httptest.NewServer(up.handler())
			t.Cleanup(backend.Close)
			logger, err := audit.New("json", "file", auditPath, true, true)
			if err != nil {
				t.Fatalf("audit logger: %v", err)
			}
			proxyAddr, p, cleanup := setupForwardProxyWithLogger(t, logger, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
			})
			t.Cleanup(cleanup)
			p.receiptEmitterPtr.Store(rph.emitter)
			installForwardTestDialer(p, backend.Listener.Addr().String())
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.example.com/v1/upload", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			req.Header.Set("Content-Type", "text/plain")
			for _, encoding := range encodings {
				req.Header.Set("Content-Encoding", encoding)
			}
			resp, err := forwardHTTPClient(t, proxyAddr).Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			logger.Close()
			if up.hits.Load() != 0 {
				t.Fatalf("upstream hits = %d, want 0", up.hits.Load())
			}
			auditLog, err := io.ReadAll(mustOpen(t, auditPath))
			if err != nil {
				t.Fatalf("read audit: %v", err)
			}
			rec := rph.requireReceipt(t, resp.Header.Get(blockreason.HeaderLayer))
			saw[tt.name] = observed{
				status:  resp.StatusCode,
				reason:  resp.Header.Get(blockreason.HeaderReason),
				layer:   resp.Header.Get(blockreason.HeaderLayer),
				audit:   string(auditLog),
				receipt: rec.ActionRecord.Layer,
			}
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
		})
	}
	compareCoded := func(identity, coded string) {
		t.Helper()
		left, right := saw[identity], saw[coded]
		if left.status != right.status || left.reason != right.reason || left.layer != right.layer || left.receipt != right.receipt {
			t.Fatalf("%s and %s differ: %+v vs %+v", identity, coded, left, right)
		}
		event := `"event":"body_prompt_injection"`
		if strings.Contains(identity, "credential") {
			event = `"event":"body_dlp"`
		}
		if !strings.Contains(left.audit, event) {
			t.Fatalf("%s audit missing %s: %s", identity, event, left.audit)
		}
		if !strings.Contains(right.audit, event) {
			t.Fatalf("%s audit missing %s: %s", coded, event, right.audit)
		}
	}
	compareCoded("identity credential", "gzip credential")
	compareCoded("identity credential", "deflate credential")
	compareCoded("identity injection", "gzip injection")
	compareCoded("identity injection", "deflate injection")
}

func mustOpen(t *testing.T, path string) io.ReadCloser {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestCompressedRequestBodiesFailClosed(t *testing.T) {
	secret := fakeAPIKey()
	clean := []byte("hello")
	gzipped := gzipRequestBody(t, clean)
	truncated := gzipped[:8]
	corrupt := append([]byte{}, gzipped...)
	corrupt[len(corrupt)-1] ^= 0xff
	plainAfter := append(append([]byte{}, gzipped...), []byte(" "+secret)...)
	second := append(append([]byte{}, gzipped...), gzipRequestBody(t, []byte(secret))...)
	zlibTrail := append(append([]byte{}, deflateRequestBody(t, clean)...), []byte(" "+secret)...)
	bomb := gzipRequestBody(t, bytes.Repeat([]byte("A"), 256))
	oversized := bytes.Repeat([]byte("Z"), 128)
	// The credential sits in the gzip header, outside the decoded body.
	headerField := func(h gzip.Header, payload []byte) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Header = h
		if _, err := zw.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	cases := []struct {
		name        string
		body        []byte
		encodings   []string
		max         int
		redact      bool
		audit       bool
		contentType string
		wantStatus  int
		wantReason  string
		wantSub     string
	}{
		{name: "decompression bomb", body: bomb, encodings: []string{"gzip"}, max: 32, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: "max_body_bytes"},
		{name: "compressed over limit", body: oversized, encodings: []string{"gzip"}, max: 32, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: "max_body_bytes"},
		{name: "truncated gzip", body: truncated, encodings: []string{"gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "corrupt crc", body: corrupt, encodings: []string{"gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "gzip then plaintext credential", body: plainAfter, encodings: []string{"gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "second gzip member credential", body: second, encodings: []string{"gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "zlib then trailing bytes", body: zlibTrail, encodings: []string{"deflate"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "credential in gzip comment", body: headerField(gzip.Header{Comment: secret}, clean), encodings: []string{"gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "credential in gzip file name", body: headerField(gzip.Header{Name: secret}, clean), encodings: []string{"gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "credential in gzip extra field", body: headerField(gzip.Header{Extra: []byte(secret)}, clean), encodings: []string{"gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "credential in gzip comment with empty body", body: headerField(gzip.Header{Comment: secret}, nil), encodings: []string{"gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "credential in gzip file name with empty body", body: headerField(gzip.Header{Name: secret}, nil), encodings: []string{"gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "credential in gzip extra field with empty body", body: headerField(gzip.Header{Extra: []byte(secret)}, nil), encodings: []string{"gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "stacked gzip", body: gzipped, encodings: []string{"gzip, gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "two header lines", body: gzipped, encodings: []string{"gzip", "gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "gzip plus identity", body: gzipped, encodings: []string{"gzip, identity"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "brotli", body: []byte(secret), encodings: []string{"br"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "zstd", body: []byte(secret), encodings: []string{"zstd"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "declared gzip is plaintext", body: []byte("token " + secret), encodings: []string{"gzip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "mixed case still scanned", body: gzipRequestBody(t, []byte(secret)), encodings: []string{"GZip"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.DLPMatch)},
		{name: "padded token still scanned", body: gzipRequestBody(t, []byte(secret)), encodings: []string{" gzip "}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.DLPMatch)},
		{name: "raw deflate", body: rawDeflateRequestBody(t, []byte(secret)), encodings: []string{"deflate"}, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
		{name: "redaction would rewrite", body: gzipRequestBody(t, []byte(`{"token":"`+secret+`"}`)), encodings: []string{"gzip"}, redact: true, contentType: "application/json", wantStatus: http.StatusForbidden, wantReason: string(blockreason.RedactionFailure), wantSub: "would be rewritten"},
		{name: "audit mode still refuses", body: []byte(secret), encodings: []string{"br"}, audit: true, wantStatus: http.StatusForbidden, wantReason: string(blockreason.ParseError), wantSub: scanner.UnscannedEncodingSuffix},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			status, respBody, hdr, up := forwardCodedRequest(t, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
				if tt.max > 0 {
					cfg.RequestBodyScanning.MaxBodyBytes = tt.max
				}
				if tt.redact {
					enableRequestRedaction(cfg)
				}
				if tt.audit {
					off := false
					cfg.Enforce = &off
				}
			}, tt.body, tt.encodings, tt.contentType)
			if status != tt.wantStatus {
				t.Fatalf("status = %d, want %d", status, tt.wantStatus)
			}
			if got := hdr.Get(blockreason.HeaderReason); got != tt.wantReason {
				t.Fatalf("reason = %q, want %q; body=%s", got, tt.wantReason, respBody)
			}
			if tt.wantSub != "" && !strings.Contains(respBody, tt.wantSub) {
				t.Fatalf("body %q does not contain %q", respBody, tt.wantSub)
			}
			if up.hits.Load() != 0 {
				t.Fatalf("upstream hits = %d, want 0", up.hits.Load())
			}
		})
	}
}

func TestCleanCodedBodyForwardedByteIdentical(t *testing.T) {
	plain := []byte(`{"ok":true}`)
	cases := []struct {
		name   string
		coding string
		body   []byte
	}{
		{name: "gzip", coding: "gzip", body: gzipRequestBody(t, plain)},
		{name: "x-gzip", coding: "x-gzip", body: gzipRequestBody(t, plain)},
		{name: "deflate", coding: "deflate", body: deflateRequestBody(t, plain)},
		{name: "empty gzip payload", coding: "gzip", body: gzipRequestBody(t, nil)},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			status, respBody, _, up := forwardCodedRequest(t, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
			}, tt.body, []string{tt.coding}, "")
			if status != http.StatusNoContent {
				t.Fatalf("status = %d, want 204; body=%s", status, respBody)
			}
			if up.hits.Load() != 1 {
				t.Fatalf("upstream hits = %d, want 1", up.hits.Load())
			}
			if up.enc != tt.coding || up.clen != int64(len(tt.body)) || !bytes.Equal(up.body, tt.body) {
				t.Fatalf("forwarded enc=%q len=%d match=%v", up.enc, up.clen, bytes.Equal(up.body, tt.body))
			}
		})
	}
}

func TestGzipRequestTrailersFailClosed(t *testing.T) {
	up := &codedUpstream{}
	backend := httptest.NewServer(up.handler())
	t.Cleanup(backend.Close)
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
	})
	t.Cleanup(cleanup)
	installForwardTestDialer(p, backend.Listener.Addr().String())

	wire := gzipRequestBody(t, []byte("hello"))
	var raw bytes.Buffer
	raw.WriteString("POST http://api.example.com/v1/upload HTTP/1.1\r\n")
	raw.WriteString("Host: api.example.com\r\n")
	raw.WriteString("Content-Type: text/plain\r\n")
	raw.WriteString("Content-Encoding: gzip\r\n")
	raw.WriteString("Transfer-Encoding: chunked\r\n")
	raw.WriteString("Trailer: X-Checksum\r\n\r\n")
	_, _ = fmt.Fprintf(&raw, "%x\r\n", len(wire))
	raw.Write(wire)
	raw.WriteString("\r\n0\r\nX-Checksum: abc\r\n\r\n")

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write(raw.Bytes()); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || up.hits.Load() != 0 {
		t.Fatalf("status=%d hits=%d body=%s", resp.StatusCode, up.hits.Load(), respBody)
	}
	if !strings.Contains(string(respBody), "request trailers cannot be scanned") {
		t.Fatalf("body = %s", respBody)
	}
}

func TestRequestPolicyDecodesCodedBody(t *testing.T) {
	plain := []byte(`{"query":"query { id }"}`)
	wire := gzipRequestBody(t, plain)
	status, respBody, _, up := forwardCodedRequest(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = false
		cfg.RequestPolicy.Enabled = true
		cfg.RequestPolicy.Rules = []config.RequestPolicyRule{graphqlBlockRule()}
	}, wire, []string{"gzip"}, "application/json")
	if status != http.StatusNoContent {
		t.Fatalf("clean gzip status = %d, want 204; body=%s", status, respBody)
	}
	if up.hits.Load() != 1 || !bytes.Equal(up.body, wire) || up.enc != "gzip" {
		t.Fatalf("hits=%d enc=%q match=%v", up.hits.Load(), up.enc, bytes.Equal(up.body, wire))
	}

	blocked := gzipRequestBody(t, []byte(deleteRecordGraphQLBody()))
	status, respBody, _, up = forwardCodedRequest(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = false
		cfg.RequestPolicy.Enabled = true
		cfg.RequestPolicy.Rules = []config.RequestPolicyRule{graphqlBlockRule()}
	}, blocked, []string{"gzip"}, "application/json")
	if status != http.StatusForbidden || up.hits.Load() != 0 {
		t.Fatalf("mutation status=%d hits=%d body=%s", status, up.hits.Load(), respBody)
	}

	status, _, _, up = forwardCodedRequest(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = false
		cfg.RequestPolicy.Enabled = true
		cfg.RequestPolicy.Rules = []config.RequestPolicyRule{graphqlBlockRule()}
	}, []byte(deleteRecordGraphQLBody()), []string{"br"}, "application/json")
	if status != http.StatusForbidden || up.hits.Load() != 0 {
		t.Fatalf("br status=%d hits=%d", status, up.hits.Load())
	}

	// Decoded size uses the same limit as the compressed input. The client-facing
	// reason is the matched rule; the size detail is recorded before that.
	longQuery := `{"query":"` + strings.Repeat("a", 400) + `"}`
	status, respBody, _, up = forwardCodedRequest(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = false
		cfg.RequestBodyScanning.MaxBodyBytes = 64
		cfg.RequestPolicy.Enabled = true
		cfg.RequestPolicy.Rules = []config.RequestPolicyRule{graphqlBlockRule()}
	}, gzipRequestBody(t, []byte(longQuery)), []string{"gzip"}, "application/json")
	if status != http.StatusForbidden || up.hits.Load() != 0 {
		t.Fatalf("decoded over limit status=%d hits=%d body=%s", status, up.hits.Load(), respBody)
	}
}

// A Content-Length of zero is not a body. The client library presents it as
// no body, so the existing no-body gate forwards it. There is no compressed
// stream for an upstream decoder to read.
func TestContentLengthZeroGzipForwardsEmpty(t *testing.T) {
	status, respBody, _, up := forwardCodedRequest(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
	}, nil, []string{"gzip"}, "")
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", status, respBody)
	}
	if up.hits.Load() != 1 || up.enc != "gzip" || len(up.body) != 0 {
		t.Fatalf("hits=%d enc=%q len=%d", up.hits.Load(), up.enc, len(up.body))
	}
}

// A chunked body of length zero still declares gzip and is read. It is not a
// gzip stream, and an upstream decoder rejects it, so the scan refuses it.
func TestChunkedEmptyGzipBodyRefused(t *testing.T) {
	up := &codedUpstream{}
	backend := httptest.NewServer(up.handler())
	t.Cleanup(backend.Close)
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
	})
	t.Cleanup(cleanup)
	installForwardTestDialer(p, backend.Listener.Addr().String())

	var raw bytes.Buffer
	raw.WriteString("POST http://api.example.com/v1/upload HTTP/1.1\r\n")
	raw.WriteString("Host: api.example.com\r\n")
	raw.WriteString("Content-Type: text/plain\r\n")
	raw.WriteString("Content-Encoding: gzip\r\n")
	raw.WriteString("Transfer-Encoding: chunked\r\n\r\n")
	raw.WriteString("0\r\n\r\n")

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write(raw.Bytes()); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || up.hits.Load() != 0 {
		t.Fatalf("status=%d hits=%d body=%s", resp.StatusCode, up.hits.Load(), respBody)
	}
	if !strings.Contains(string(respBody), scanner.UnscannedEncodingSuffix) {
		t.Fatalf("body = %s", respBody)
	}
}

func TestPrepareRequestPolicyBodyDecodesSupportedCoding(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(graphqlBlockRule()))
	plain := []byte(deleteRecordGraphQLBody())
	wire := gzipRequestBody(t, plain)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	in := requestPolicyInput{
		Host: rpTestHost, Method: http.MethodPost, Path: "/graphql",
		ContentType: "application/json", Headers: req.Header, AuditCtx: audit.LogContext{},
	}
	if res := p.prepareRequestPolicyBody(req, &in); res.Block {
		t.Fatalf("prepare blocked a decodable body: %+v", res)
	}
	if !in.WireBodySet || !bytes.Equal(in.Body, plain) || !bytes.Equal(in.WireBody, wire) {
		t.Fatalf("wire set=%v inspected match=%v wire match=%v", in.WireBodySet, bytes.Equal(in.Body, plain), bytes.Equal(in.WireBody, wire))
	}
	forwarded, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read rewrapped body: %v", err)
	}
	if !bytes.Equal(forwarded, wire) {
		t.Fatal("rewrapped body is not the original gzip bytes")
	}
	replay, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody: %v", err)
	}
	replayed, err := io.ReadAll(replay)
	_ = replay.Close()
	if err != nil {
		t.Fatalf("read GetBody: %v", err)
	}
	if !bytes.Equal(replayed, wire) {
		t.Fatal("GetBody replay is not the original gzip bytes")
	}

	cfg := reqPolicyConfig(graphqlBlockRule())
	cfg.RequestBodyScanning.MaxBodyBytes = 64
	limited := newTestProxyWithConfig(t, cfg)
	big := gzipRequestBody(t, bytes.Repeat([]byte("a"), 400))
	if len(big) > 64 {
		t.Fatalf("fixture compressed size = %d, want it under the limit so the decoded size is what refuses", len(big))
	}
	over := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql", bytes.NewReader(big))
	over.Header.Set("Content-Type", "application/json")
	over.Header.Set("Content-Encoding", "gzip")
	overIn := requestPolicyInput{
		Host: rpTestHost, Method: http.MethodPost, Path: "/graphql",
		ContentType: "application/json", Headers: over.Header, AuditCtx: audit.LogContext{},
	}
	if res := limited.prepareRequestPolicyBody(over, &overIn); !res.Block {
		t.Fatal("decoded body over max_body_bytes should block")
	}

	declared := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql", strings.NewReader("not gzip"))
	declared.Header.Set("Content-Type", "application/json")
	declared.Header.Set("Content-Encoding", "gzip")
	declaredIn := requestPolicyInput{
		Host: rpTestHost, Method: http.MethodPost, Path: "/graphql",
		ContentType: "application/json", Headers: declared.Header, AuditCtx: audit.LogContext{},
	}
	if res := p.prepareRequestPolicyBody(declared, &declaredIn); !res.Block {
		t.Fatal("plaintext declared as gzip should block")
	}
}

func TestReversePolicyForwardsOriginalGzip(t *testing.T) {
	var got []byte
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got = append([]byte(nil), body...)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	rule := graphqlBlockRule()
	rule.Route.Hosts = []string{upstreamURL.Hostname()}
	cfg := reqPolicyConfig(rule)
	cfg.RequestBodyScanning.Enabled = false
	p := newTestProxyWithConfig(t, cfg)
	handler := NewReverseProxy(upstreamURL, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
	handler.SetRequestPolicyFn(p.ApplyRequestPolicy)
	handler.SetRequestPolicyPrepareFn(p.PrepareRequestPolicyBody)

	plain := []byte(`{"query":"query { id }"}`)
	wire := gzipRequestBody(t, plain)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql", bytes.NewReader(wire))
	req.Host = rpTestHost
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || hits.Load() != 1 || !bytes.Equal(got, wire) {
		t.Fatalf("status=%d hits=%d match=%v body=%s", w.Code, hits.Load(), bytes.Equal(got, wire), w.Body.String())
	}

	hits.Store(0)
	blocked := gzipRequestBody(t, []byte(deleteRecordGraphQLBody()))
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql", bytes.NewReader(blocked))
	req.Host = rpTestHost
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("mutation status=%d hits=%d body=%s", w.Code, hits.Load(), w.Body.String())
	}
}

type codedObservation struct {
	status  int
	reason  string
	layer   string
	audit   string
	receipt string
	hits    int32
	body    []byte
	enc     string
}

func compareCodedObservation(t *testing.T, identity, coded codedObservation, event string) {
	t.Helper()
	if identity.status != coded.status || identity.reason != coded.reason || identity.layer != coded.layer || identity.receipt != coded.receipt {
		t.Fatalf("identity and coded differ:\nidentity=%+v\ncoded=%+v", identity, coded)
	}
	if event != "" && (!strings.Contains(identity.audit, event) || !strings.Contains(coded.audit, event)) {
		t.Fatalf("audit missing %s\nidentity=%s\ncoded=%s", event, identity.audit, coded.audit)
	}
}

func codedAuditLogger(t *testing.T) (string, *audit.Logger) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", path, true, true)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	return path, logger
}

func codedAuditText(t *testing.T, logger *audit.Logger, path string) string {
	t.Helper()
	logger.Close()
	buf, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	return string(buf)
}

func finishCodedObservation(t *testing.T, resp *http.Response, logger *audit.Logger, auditPath string, rph *receiptProxyHelper, hits int32, body []byte, enc string) codedObservation {
	t.Helper()
	obs := codedObservation{
		status: resp.StatusCode,
		reason: resp.Header.Get(blockreason.HeaderReason),
		layer:  resp.Header.Get(blockreason.HeaderLayer),
		hits:   hits,
		body:   append([]byte(nil), body...),
		enc:    enc,
		audit:  codedAuditText(t, logger, auditPath),
	}
	if resp.StatusCode == http.StatusForbidden && obs.layer != "" {
		obs.receipt = rph.requireReceipt(t, obs.layer).ActionRecord.Layer
	}
	return obs
}

func observeInterceptUpload(t *testing.T, plain []byte, coding string, wrap func(*testing.T, []byte) []byte) codedObservation {
	t.Helper()
	body := append([]byte(nil), plain...)
	if wrap != nil {
		body = wrap(t, plain)
	}
	var got []byte
	var enc string
	var hits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got = append([]byte(nil), buf...)
		enc = r.Header.Get("Content-Encoding")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cache, pool, cfg, _, _, m := testInterceptSetup(t)
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	sc := scanner.MustNew(cfg)
	t.Cleanup(func() { sc.Close() })
	auditPath, logger := codedAuditLogger(t)
	proxy, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	t.Cleanup(proxy.Close)
	rph := newReceiptProxyHelper(t)
	proxy.receiptEmitterPtr.Store(rph.emitter)

	addr := upstream.Listener.Addr().String()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+"/api", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	if coding != "" {
		req.Header.Set("Content-Encoding", coding)
	}
	resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, proxy)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return finishCodedObservation(t, resp, logger, auditPath, rph, hits.Load(), got, enc)
}

func observeReverseUpload(t *testing.T, plain []byte, coding string, wrap func(*testing.T, []byte) []byte) codedObservation {
	t.Helper()
	body := append([]byte(nil), plain...)
	if wrap != nil {
		body = wrap(t, plain)
	}
	cfg := reverseTestConfig()
	cfg.RequestBodyScanning.Action = config.ActionBlock
	var got []byte
	var enc string
	var hits atomic.Int32
	upstream := func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got = append([]byte(nil), buf...)
		enc = r.Header.Get("Content-Encoding")
		w.WriteHeader(http.StatusOK)
	}
	proxy, handler := reverseTestSetupWithHandler(t, cfg, upstream)
	auditPath, logger := codedAuditLogger(t)
	handler.logger = logger
	rph := newReceiptProxyHelper(t)
	var emitterPtr atomic.Pointer[receipt.Emitter]
	emitterPtr.Store(rph.emitter)
	handler.SetReceiptEmitter(&emitterPtr)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxy.URL+"/api/send", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	if coding != "" {
		req.Header.Set("Content-Encoding", coding)
	}
	req.ContentLength = int64(len(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	_, _ = io.Copy(io.Discard, resp.Body)
	return finishCodedObservation(t, resp, logger, auditPath, rph, hits.Load(), got, enc)
}

func TestInterceptAndReverseCodedBodiesMatchIdentity(t *testing.T) {
	secret := fakeAPIKey()
	surfaces := []struct {
		name string
		run  func(*testing.T, []byte, string, func(*testing.T, []byte) []byte) codedObservation
	}{
		{name: "intercept", run: observeInterceptUpload},
		{name: "reverse", run: observeReverseUpload},
	}
	findings := []struct {
		name  string
		plain string
		event string
	}{
		{name: "credential", plain: secret, event: `"event":"body_dlp"`},
		{name: "injection", plain: testInjectionPayload, event: `"event":"body_prompt_injection"`},
	}
	codings := []struct {
		name string
		wrap func(*testing.T, []byte) []byte
	}{
		{name: "gzip", wrap: gzipRequestBody},
		{name: "deflate", wrap: deflateRequestBody},
	}
	for _, surface := range surfaces {
		for _, finding := range findings {
			for _, coding := range codings {
				t.Run(surface.name+"/"+finding.name+"/"+coding.name, func(t *testing.T) {
					identity := surface.run(t, []byte(finding.plain), "", nil)
					coded := surface.run(t, []byte(finding.plain), coding.name, coding.wrap)
					event := finding.event
					// Intercept records the finding on the blocked event's scanner
					// field. The dedicated body event is not emitted on that path.
					if surface.name == "intercept" {
						event = strings.Replace(finding.event, `"event":`, `"scanner":`, 1)
					}
					compareCodedObservation(t, identity, coded, event)
					if identity.hits != 0 || coded.hits != 0 {
						t.Fatalf("upstream hits identity=%d coded=%d", identity.hits, coded.hits)
					}
				})
			}
		}
		for _, coding := range codings {
			t.Run(surface.name+"/clean/"+coding.name, func(t *testing.T) {
				plain := []byte(`{"ok":true}`)
				wire := coding.wrap(t, plain)
				got := surface.run(t, plain, coding.name, coding.wrap)
				if got.status != http.StatusOK || got.hits != 1 || got.enc != coding.name || !bytes.Equal(got.body, wire) {
					t.Fatalf("status=%d hits=%d enc=%q match=%v", got.status, got.hits, got.enc, bytes.Equal(got.body, wire))
				}
			})
		}
	}
}

func a2aTextMessage(text string) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":"request","method":"message/send","params":{"message":{"messageId":"message","role":"user","parts":[{"kind":"text","text":%q}]}}}`, text))
}

func observeForwardA2A(t *testing.T, plain []byte, coding string, wrap func(*testing.T, []byte) []byte, bodyScanning bool) codedObservation {
	t.Helper()
	body := append([]byte(nil), plain...)
	if wrap != nil {
		body = wrap(t, plain)
	}
	var got []byte
	var enc string
	var hits atomic.Int32
	backend := newForwardA2ATestBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got = append([]byte(nil), buf...)
		enc = r.Header.Get("Content-Encoding")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"request","result":{}}`))
	}))
	t.Cleanup(backend.Close)
	auditPath, logger := codedAuditLogger(t)
	rph := newReceiptProxyHelper(t)
	proxyAddr, proxy, cleanup := setupForwardProxyWithLogger(t, logger, func(cfg *config.Config) {
		cfg.A2AScanning.Enabled = true
		cfg.A2AScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.Enabled = bodyScanning
		cfg.RequestBodyScanning.Action = config.ActionBlock
	})
	t.Cleanup(cleanup)
	proxy.receiptEmitterPtr.Store(rph.emitter)
	installForwardTestDialer(proxy, backend.Listener.Addr().String())

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.example.com/message:send", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/a2a+json")
	if coding != "" {
		req.Header.Set("Content-Encoding", coding)
	}
	resp, err := forwardHTTPClient(t, proxyAddr).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	_, _ = io.Copy(io.Discard, resp.Body)
	return finishCodedObservation(t, resp, logger, auditPath, rph, hits.Load(), got, enc)
}

func TestForwardA2ACodedBodiesMatchIdentity(t *testing.T) {
	findings := []struct {
		name  string
		plain []byte
		event string
	}{
		{name: "credential", plain: a2aTextMessage(fakeAPIKey()), event: `"event":"body_dlp"`},
		{name: "injection", plain: a2aTextMessage(testInjectionPayload), event: `"event":"body_prompt_injection"`},
	}
	codings := []struct {
		name string
		wrap func(*testing.T, []byte) []byte
	}{
		{name: "gzip", wrap: gzipRequestBody},
		{name: "deflate", wrap: deflateRequestBody},
	}
	for _, scanning := range []bool{true, false} {
		eventFor := func(findingEvent string) string {
			if scanning {
				return findingEvent
			}
			return `"scanner":"a2a_scan"`
		}
		for _, finding := range findings {
			for _, coding := range codings {
				t.Run(fmt.Sprintf("body_scanning=%t/%s/%s", scanning, finding.name, coding.name), func(t *testing.T) {
					identity := observeForwardA2A(t, finding.plain, "", nil, scanning)
					coded := observeForwardA2A(t, finding.plain, coding.name, coding.wrap, scanning)
					compareCodedObservation(t, identity, coded, eventFor(finding.event))
					if identity.hits != 0 || coded.hits != 0 {
						t.Fatalf("upstream hits identity=%d coded=%d", identity.hits, coded.hits)
					}
				})
			}
		}
		for _, coding := range codings {
			t.Run(fmt.Sprintf("body_scanning=%t/clean/%s", scanning, coding.name), func(t *testing.T) {
				plain := a2aTextMessage("hello")
				wire := coding.wrap(t, plain)
				got := observeForwardA2A(t, plain, coding.name, coding.wrap, scanning)
				if got.status != http.StatusOK || got.hits != 1 || got.enc != coding.name || !bytes.Equal(got.body, wire) {
					t.Fatalf("status=%d hits=%d enc=%q match=%v body=%s", got.status, got.hits, got.enc, bytes.Equal(got.body, wire), got.audit)
				}
			})
		}
	}
}

// With redaction on and nothing to redact, a compressed JSON body is forwarded
// as sent. The redaction rewrite re-encodes a document even when it changes
// no value, so ordinary client JSON (unsorted keys, spacing) must not be
// taken for a rewrite.
func TestCleanGzipJSONWithRedactionForwardsWhenUnchanged(t *testing.T) {
	for name, document := range map[string]string{
		"compact sorted":  `{"ok":true}`,
		"unsorted keys":   `{"model":"x","messages":[],"b":1,"a":2}`,
		"spaced":          `{ "a" : 1, "list" : [ 1, 2 ] }`,
		"pretty printed":  "{\n  \"model\": \"x\",\n  \"messages\": []\n}\n",
		"escaped unicode": `{"note":"caf\u00e9"}`,
	} {
		t.Run(name, func(t *testing.T) {
			wire := gzipRequestBody(t, []byte(document))
			status, respBody, _, up := forwardCodedRequest(t, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
				enableRequestRedaction(cfg)
			}, wire, []string{"gzip"}, "application/json")
			if status != http.StatusNoContent || up.hits.Load() != 1 || !bytes.Equal(up.body, wire) {
				t.Fatalf("status=%d hits=%d match=%v body=%s", status, up.hits.Load(), bytes.Equal(up.body, wire), respBody)
			}
		})
	}
}

// With redaction on, a credential in a compressed JSON body that redaction
// would not rewrite is still found by the scan of the decoded body. A
// duplicate key keeps both values in view, since the original bytes are what
// the upstream receives.
func TestGzipJSONWithRedactionStillScansDecodedBody(t *testing.T) {
	secret := fakeAPIKey()
	wire := gzipRequestBody(t, []byte(`{"note":"`+secret+`","note":"harmless"}`))
	status, respBody, hdr, up := forwardCodedRequest(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		enableRequestRedaction(cfg)
	}, wire, []string{"gzip"}, "application/json")
	if status != http.StatusForbidden || up.hits.Load() != 0 {
		t.Fatalf("status=%d hits=%d reason=%q body=%s", status, up.hits.Load(), hdr.Get(blockreason.HeaderReason), respBody)
	}
}

func TestRequestPolicyBodyViewAndInspectedSwap(t *testing.T) {
	if got := requestPolicyBodyView([]byte("wire"), nil, true); got == nil || len(got) != 0 {
		t.Fatalf("nil inspected view = %q", got)
	}
	if got := requestPolicyBodyView([]byte("wire"), []byte("plain"), false); string(got) != "wire" {
		t.Fatalf("identity view = %q", got)
	}
	if got := inspectedBodyForCaller([]byte("wire"), BodyScanResult{}); got != nil {
		t.Fatalf("identity caller view = %q, want nil", got)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.example.com/v1/upload", bytes.NewReader([]byte("wire")))
	req.Header.Set("Content-Encoding", "gzip")
	var saw string
	callWithInspectedBody(req, nil, func() {
		buf, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read inspected: %v", err)
		}
		replay, err := req.GetBody()
		if err != nil {
			t.Fatalf("GetBody: %v", err)
		}
		defer func() { _ = replay.Close() }()
		again, err := io.ReadAll(replay)
		if err != nil {
			t.Fatalf("read replay: %v", err)
		}
		if len(buf) != 0 || len(again) != 0 {
			t.Fatalf("inspected view = %q replay = %q", buf, again)
		}
		saw = "ran"
	})
	if saw != "ran" {
		t.Fatal("inspected body function did not run")
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(restored) != "wire" || req.Header.Get("Content-Encoding") != "gzip" || req.ContentLength != 4 {
		t.Fatalf("restored body=%q encoding=%q len=%d", restored, req.Header.Get("Content-Encoding"), req.ContentLength)
	}
}

func TestInterceptA2ACodedBodyMatchesIdentity(t *testing.T) {
	observe := func(t *testing.T, plain []byte, coding string) codedObservation {
		t.Helper()
		body := append([]byte(nil), plain...)
		if coding != "" {
			body = gzipRequestBody(t, plain)
		}
		var got []byte
		var enc string
		var hits atomic.Int32
		upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			buf, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read upstream body: %v", err)
			}
			got = append([]byte(nil), buf...)
			enc = r.Header.Get("Content-Encoding")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"request","result":{}}`))
		}))
		t.Cleanup(upstream.Close)

		cache, pool, cfg, _, _, m := testInterceptSetup(t)
		cfg.A2AScanning.Enabled = true
		cfg.A2AScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.Enabled = false
		sc := scanner.MustNew(cfg)
		t.Cleanup(func() { sc.Close() })
		auditPath, logger := codedAuditLogger(t)
		proxy, err := New(cfg, logger, sc, m)
		if err != nil {
			t.Fatalf("proxy: %v", err)
		}
		t.Cleanup(proxy.Close)
		rph := newReceiptProxyHelper(t)
		proxy.receiptEmitterPtr.Store(rph.emitter)

		addr := upstream.Listener.Addr().String()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+"/message:send", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		req.Header.Set("Content-Type", "application/a2a+json")
		if coding != "" {
			req.Header.Set("Content-Encoding", coding)
		}
		resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, proxy)
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return finishCodedObservation(t, resp, logger, auditPath, rph, hits.Load(), got, enc)
	}

	t.Run("credential", func(t *testing.T) {
		plain := a2aTextMessage(fakeAPIKey())
		identity := observe(t, plain, "")
		coded := observe(t, plain, "gzip")
		compareCodedObservation(t, identity, coded, `"scanner":"a2a_scan"`)
		if identity.hits != 0 || coded.hits != 0 {
			t.Fatalf("hits identity=%d coded=%d", identity.hits, coded.hits)
		}
	})
	t.Run("clean", func(t *testing.T) {
		plain := a2aTextMessage("hello")
		wire := gzipRequestBody(t, plain)
		got := observe(t, plain, "gzip")
		if got.status != http.StatusOK || got.hits != 1 || got.enc != "gzip" || !bytes.Equal(got.body, wire) {
			t.Fatalf("status=%d hits=%d enc=%q match=%v", got.status, got.hits, got.enc, bytes.Equal(got.body, wire))
		}
	})
}

func TestScanRequestBody_TextFreeJSONFinishesClean(t *testing.T) {
	t.Parallel()
	cfg := testScannerConfig()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	buf, result := scanRequestBody(t.Context(), BodyScanRequest{
		Body:        strings.NewReader(`{}`),
		ContentType: "application/json",
		MaxBytes:    1024,
		Scanner:     sc,
	})
	if !result.Clean || string(buf) != "{}" || result.ContentCoding != "" {
		t.Fatalf("clean=%v coding=%q buf=%q reason=%s", result.Clean, result.ContentCoding, buf, result.Reason)
	}
}

func TestReadForwardBodyForProtocolScanBounds(t *testing.T) {
	t.Parallel()
	_, _, _, err := readForwardBodyForProtocolScan(strings.NewReader("x"), "br", 32, nil)
	if err == nil || !strings.Contains(err.Error(), "compressed bodies cannot be scanned") {
		t.Fatalf("unsupported coding: %v", err)
	}

	plain := bytes.Repeat([]byte("A"), 400)
	wire := gzipRequestBody(t, plain)
	if len(wire) > 64 {
		t.Fatalf("compressed fixture is %d bytes, want it under the limit", len(wire))
	}
	_, _, _, err = readForwardBodyForProtocolScan(bytes.NewReader(wire), "gzip", 64, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds max_body_bytes") {
		t.Fatalf("decoded over limit: %v", err)
	}

	_, _, _, err = readForwardBodyForProtocolScan(bytes.NewReader(bytes.Repeat([]byte("Z"), 40)), "gzip", 32, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds max_body_bytes") {
		t.Fatalf("compressed over limit: %v", err)
	}

	gotWire, gotInspected, decoded, err := readForwardBodyForProtocolScan(strings.NewReader("abc"), "", 32, nil)
	if err != nil || decoded || string(gotWire) != "abc" || string(gotInspected) != "abc" {
		t.Fatalf("identity wire=%q inspected=%q decoded=%v err=%v", gotWire, gotInspected, decoded, err)
	}

	_, _, _, err = readForwardBodyForProtocolScan(protocolScanFailReader{}, "", 32, nil)
	if err == nil || !strings.Contains(err.Error(), "error reading request body") {
		t.Fatalf("read error: %v", err)
	}
}

type protocolScanFailReader struct{}

func (protocolScanFailReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestForwardA2AGzipRedirectReplaysOriginalBody(t *testing.T) {
	plain := a2aTextMessage("hello")
	wire := gzipRequestBody(t, plain)
	var hits atomic.Int32
	var got []byte
	var enc string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/message:send" {
			http.Redirect(w, r, "http://api.example.com/final", http.StatusTemporaryRedirect)
			return
		}
		hits.Add(1)
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got = append([]byte(nil), buf...)
		enc = r.Header.Get("Content-Encoding")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(backend.Close)

	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.A2AScanning.Enabled = true
		cfg.A2AScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.Enabled = false
	})
	t.Cleanup(cleanup)
	installForwardTestDialer(p, backend.Listener.Addr().String())

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.example.com/message:send", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/a2a+json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := forwardHTTPClient(t, proxyAddr).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent || hits.Load() != 1 || enc != "gzip" || !bytes.Equal(got, wire) {
		t.Fatalf("status=%d hits=%d enc=%q match=%v body=%s", resp.StatusCode, hits.Load(), enc, bytes.Equal(got, wire), respBody)
	}
}

func reverseGzipCrossRequest(t *testing.T, bodyScanning bool) {
	t.Helper()
	cfg := reverseParityBaseConfig(t)
	cfg.RequestBodyScanning.Enabled = bodyScanning
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.CrossRequestDetection = ceeFragmentBlockCfg()
	cfg.Taint.Enabled = false
	var got []byte
	rp, _, _ := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got = append([]byte(nil), body...)
		w.WriteHeader(http.StatusOK)
	})
	send := func(plain string) (*httptest.ResponseRecorder, []byte) {
		t.Helper()
		wire := gzipRequestBody(t, []byte(plain))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://reverse.example/upload", bytes.NewReader(wire))
		req.RemoteAddr = "10.0.0.9:5555"
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("Content-Encoding", "gzip")
		rec := httptest.NewRecorder()
		rp.ServeHTTP(rec, req)
		return rec, wire
	}
	first, wire := send(testCEEAWSKeyPrefix)
	if first.Code != http.StatusOK || !bytes.Equal(got, wire) {
		t.Fatalf("first status=%d wire match=%v body=%s", first.Code, bytes.Equal(got, wire), first.Body.String())
	}
	second, _ := send(testCEEAWSKeySuffix)
	if second.Code != http.StatusForbidden || second.Header().Get(blockreason.HeaderLayer) != "cross_request" {
		t.Fatalf("second status=%d layer=%q body=%s", second.Code, second.Header().Get(blockreason.HeaderLayer), second.Body.String())
	}
}

func forwardGzipCrossRequest(t *testing.T, bodyScanning bool) {
	t.Helper()
	var got []byte
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got = append([]byte(nil), body...)
		if r.ContentLength != int64(len(body)) {
			t.Errorf("content-length=%d body=%d", r.ContentLength, len(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	proxyAddr, proxy, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = bodyScanning
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.CrossRequestDetection = ceeFragmentBlockCfg()
		cfg.Taint.Enabled = false
	})
	t.Cleanup(cleanup)
	installForwardTestDialer(proxy, backend.Listener.Addr().String())
	client := forwardHTTPClient(t, proxyAddr)

	send := func(plain string) (*http.Response, []byte) {
		t.Helper()
		wire := gzipRequestBody(t, []byte(plain))
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.example.com/upload", bytes.NewReader(wire))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("Content-Encoding", "gzip")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp, wire
	}
	first, wire := send(testCEEAWSKeyPrefix)
	defer func() { _ = first.Body.Close() }()
	if first.StatusCode != http.StatusOK || !bytes.Equal(got, wire) {
		t.Fatalf("first status=%d wire match=%v", first.StatusCode, bytes.Equal(got, wire))
	}
	second, _ := send(testCEEAWSKeySuffix)
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusForbidden || second.Header.Get(blockreason.HeaderLayer) != "cross_request" {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("second status=%d layer=%q body=%s", second.StatusCode, second.Header.Get(blockreason.HeaderLayer), body)
	}
}

func interceptGzipCrossRequest(t *testing.T, bodyScanning bool) {
	t.Helper()
	var got []byte
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got = append([]byte(nil), body...)
		if r.ContentLength != int64(len(body)) {
			t.Errorf("content-length=%d body=%d", r.ContentLength, len(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.RequestBodyScanning.Enabled = bodyScanning
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	cfg.CrossRequestDetection = ceeFragmentBlockCfg()
	cfg.Taint.Enabled = false
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	proxy, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	t.Cleanup(proxy.Close)

	send := func(plain string) (*http.Response, []byte) {
		t.Helper()
		wire := gzipRequestBody(t, []byte(plain))
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+upstream.Listener.Addr().String()+"/upload", bytes.NewReader(wire))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("Content-Encoding", "gzip")
		resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, proxy)
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp, wire
	}
	first, wire := send(testCEEAWSKeyPrefix)
	defer func() { _ = first.Body.Close() }()
	if first.StatusCode != http.StatusOK || !bytes.Equal(got, wire) {
		t.Fatalf("first status=%d wire match=%v", first.StatusCode, bytes.Equal(got, wire))
	}
	second, _ := send(testCEEAWSKeySuffix)
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusForbidden || second.Header.Get(blockreason.HeaderLayer) != "cross_request" {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("second status=%d layer=%q body=%s", second.StatusCode, second.Header.Get(blockreason.HeaderLayer), body)
	}
}

// Cross-request detection reads the decoded text of a gzip body whether or
// not request body scanning buffered it. A credential split across two
// compressed requests is refused on the second, and the first is forwarded
// byte for byte.
func TestGzipBodyUsesDecodedViewForCrossRequestDetection(t *testing.T) {
	for _, bodyScanning := range []bool{true, false} {
		name := fmt.Sprintf("body_scanning=%t", bodyScanning)
		t.Run("reverse/"+name, func(t *testing.T) { reverseGzipCrossRequest(t, bodyScanning) })
		t.Run("forward/"+name, func(t *testing.T) { forwardGzipCrossRequest(t, bodyScanning) })
		t.Run("intercept/"+name, func(t *testing.T) { interceptGzipCrossRequest(t, bodyScanning) })
	}
}

// A gzip body whose decoded size sits between two limits must follow the
// config the request was admitted under. The reload is published after URL
// admission and before the policy body read. The compressed size is under
// both limits, so only the decoded-size check can tell them apart.
func TestCompressedPolicyBodyUsesAdmittedLimit(t *testing.T) {
	plain := []byte(`{"query":"query { id }","pad":"` + strings.Repeat("a", 400) + `"}`)
	wire := gzipRequestBody(t, plain)
	const small = 80
	const large = 1 << 20
	if len(wire) >= small || len(plain) <= small || len(plain) >= large {
		t.Fatalf("fixture wire=%d plain=%d, want wire < %d and plain between the limits", len(wire), len(plain), small)
	}

	cases := []struct {
		name         string
		admitted     int
		live         int
		wantUpstream bool
	}{
		{name: "reload raised the limit", admitted: small, live: large, wantUpstream: false},
		{name: "reload lowered the limit", admitted: large, live: small, wantUpstream: true},
	}
	for _, tc := range cases {
		t.Run("forward/"+tc.name, func(t *testing.T) {
			status, hits := forwardAdmittedGzipPolicy(t, tc.admitted, tc.live, wire)
			if tc.wantUpstream {
				if status != http.StatusOK || hits != 1 {
					t.Fatalf("status=%d hits=%d, want 200 and the original gzip forwarded", status, hits)
				}
				return
			}
			if status != http.StatusForbidden || hits != 0 {
				t.Fatalf("status=%d hits=%d, want 403 and no upstream request", status, hits)
			}
		})
		t.Run("intercept/"+tc.name, func(t *testing.T) {
			status, hits := interceptAdmittedGzipPolicy(t, tc.admitted, tc.live, wire)
			if tc.wantUpstream {
				if status != http.StatusOK || hits != 1 {
					t.Fatalf("status=%d hits=%d, want 200 and the original gzip forwarded", status, hits)
				}
				return
			}
			if status != http.StatusForbidden || hits != 0 {
				t.Fatalf("status=%d hits=%d, want 403 and no upstream request", status, hits)
			}
		})
		t.Run("reverse/"+tc.name, func(t *testing.T) {
			status, hits := reverseAdmittedGzipPolicy(t, tc.admitted, tc.live, wire)
			if tc.wantUpstream {
				if status != http.StatusOK || hits != 1 {
					t.Fatalf("status=%d hits=%d, want 200 and the original gzip forwarded", status, hits)
				}
				return
			}
			if status != http.StatusForbidden || hits != 0 {
				t.Fatalf("status=%d hits=%d, want 403 and no upstream request", status, hits)
			}
		})
	}
}

func policyConfigForHost(host string, limit int) *config.Config {
	rule := graphqlBlockRule()
	rule.Route.Hosts = []string{host}
	cfg := reqPolicyConfig(rule)
	cfg.RequestBodyScanning.Enabled = false
	cfg.RequestBodyScanning.MaxBodyBytes = limit
	return cfg
}

// publishLiveBodyLimitOnScan stores live when the URL scan finishes. That is
// after the handler has snapshotted the admitted config and before request
// policy reads the body.
func publishLiveBodyLimitOnScan(t *testing.T, p *Proxy, live *config.Config) *atomic.Bool {
	t.Helper()
	sc := p.scannerPtr.Load()
	if sc == nil {
		t.Fatal("scanner missing")
	}
	fired := &atomic.Bool{}
	sc.SetHeartbeat(func() {
		fired.Store(true)
		p.cfgPtr.Store(live)
	})
	return fired
}

func assertAdmittedLimitHeld(t *testing.T, fired *atomic.Bool, p *Proxy, admitted, live *config.Config) {
	t.Helper()
	if !fired.Load() {
		t.Fatal("reload did not run between admission and the body read")
	}
	if p.cfgPtr.Load() != live {
		t.Fatal("live config was not the one published")
	}
	if admitted.RequestBodyScanning.MaxBodyBytes == live.RequestBodyScanning.MaxBodyBytes {
		t.Fatal("admitted and live limits are the same")
	}
}

func forwardAdmittedGzipPolicy(t *testing.T, admittedLimit, liveLimit int, wire []byte) (int, int32) {
	t.Helper()
	var hits atomic.Int32
	var got []byte
	var enc string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got = append([]byte(nil), buf...)
		enc = r.Header.Get("Content-Encoding")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	admitted := policyConfigForHost(rpTestHost, admittedLimit)
	live := *admitted
	live.RequestBodyScanning.MaxBodyBytes = liveLimit
	p := newTestProxyWithConfig(t, admitted)
	installForwardTestDialer(p, upstream.Listener.Addr().String())
	fired := publishLiveBodyLimitOnScan(t, p, &live)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	p.handleForwardHTTP(w, req)
	assertAdmittedLimitHeld(t, fired, p, admitted, &live)
	if hits.Load() == 1 && (enc != "gzip" || !bytes.Equal(got, wire)) {
		t.Fatalf("forwarded enc=%q match=%v", enc, bytes.Equal(got, wire))
	}
	return w.Code, hits.Load()
}

func interceptAdmittedGzipPolicy(t *testing.T, admittedLimit, liveLimit int, wire []byte) (int, int32) {
	t.Helper()
	var hits atomic.Int32
	var got []byte
	var enc string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got = append([]byte(nil), buf...)
		enc = r.Header.Get("Content-Encoding")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	host := upstream.Listener.Addr().(*net.TCPAddr).IP.String()
	cache, pool, base, _, logger, _ := testInterceptSetup(t)
	admitted := policyConfigForHost(host, admittedLimit)
	admitted.TLSInterception = base.TLSInterception
	admitted.SSRF.IPAllowlist = append([]string(nil), base.SSRF.IPAllowlist...)
	live := *admitted
	live.RequestBodyScanning.MaxBodyBytes = liveLimit
	p := newTestProxyWithConfig(t, admitted)
	fired := publishLiveBodyLimitOnScan(t, p, &live)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+upstream.Listener.Addr().String()+"/graphql", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp := interceptAndRequestWithProxy(t, upstream, cache, pool, admitted, p.scannerPtr.Load(), logger, p.metrics, req, p)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	assertAdmittedLimitHeld(t, fired, p, admitted, &live)
	if hits.Load() == 1 && (enc != "gzip" || !bytes.Equal(got, wire)) {
		t.Fatalf("forwarded enc=%q match=%v", enc, bytes.Equal(got, wire))
	}
	return resp.StatusCode, hits.Load()
}

func reverseAdmittedGzipPolicy(t *testing.T, admittedLimit, liveLimit int, wire []byte) (int, int32) {
	t.Helper()
	var hits atomic.Int32
	var got []byte
	var enc string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got = append([]byte(nil), buf...)
		enc = r.Header.Get("Content-Encoding")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	admitted := policyConfigForHost(upstreamURL.Hostname(), admittedLimit)
	live := *admitted
	live.RequestBodyScanning.MaxBodyBytes = liveLimit
	p := newTestProxyWithConfig(t, admitted)
	handler := NewReverseProxy(upstreamURL, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
	handler.SetRequestPolicyFn(p.ApplyRequestPolicy)
	// The generic reverse path does not scan the operator-chosen upstream, so
	// the URL-scan heartbeat never runs. Publish the reloaded config at the
	// start of the body read, after ServeHTTP has snapshotted admission.
	fired := &atomic.Bool{}
	handler.SetRequestPolicyPrepareFn(func(r *http.Request, in *requestPolicyInput) requestPolicyResult {
		fired.Store(true)
		p.cfgPtr.Store(&live)
		return p.PrepareRequestPolicyBody(r, in)
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql", bytes.NewReader(wire))
	req.Host = rpTestHost
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assertAdmittedLimitHeld(t, fired, p, admitted, &live)
	if hits.Load() == 1 && (enc != "gzip" || !bytes.Equal(got, wire)) {
		t.Fatalf("forwarded enc=%q match=%v", enc, bytes.Equal(got, wire))
	}
	return w.Code, hits.Load()
}

// ceeInspectedBody returns the decoded text for a clean supported stream and
// keeps everything else a sender controls apart from it.
func TestCEEInspectedBody(t *testing.T) {
	plain := []byte(strings.Repeat("inspect this text ", 40))
	second := []byte("second member text")
	gzipped := gzipRequestBody(t, plain)
	deflated := deflateRequestBody(t, plain)
	withFields := func(h gzip.Header, payload []byte) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Header = h
		if _, err := zw.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	fielded := withFields(gzip.Header{Name: "name-field", Comment: "comment-field", Extra: []byte("extra-field")}, plain)
	laterFields := withFields(gzip.Header{Comment: "later-comment"}, second)
	stamped := withFields(gzip.Header{ModTime: time.Unix(0x64636261, 0)}, nil)
	laterStamp := withFields(gzip.Header{ModTime: time.Unix(0x68676665, 0)}, second)
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	truncated := gzipped[:len(gzipped)-12]
	cases := []struct {
		name     string
		encoding []string
		wire     []byte
		wantText []byte
		want     map[string]string
	}{
		{name: "identity", wire: plain, wantText: plain},
		{name: "gzip", encoding: []string{"gzip"}, wire: gzipped, wantText: plain},
		{name: "deflate", encoding: []string{"deflate"}, wire: deflated, wantText: plain},
		{name: "unsupported coding", encoding: []string{"br"}, wire: gzipped, wantText: gzipped},
		{name: "stacked coding", encoding: []string{"gzip", "gzip"}, wire: gzipped, wantText: gzipped},
		{name: "declared gzip is not gzip", encoding: []string{"gzip"}, wire: plain, wantText: plain},
		{name: "bytes after gzip", encoding: []string{"gzip"}, wire: join(gzipped, []byte("tail")), wantText: plain, want: map[string]string{ceeCodingRestStream: "tail"}},
		{name: "bytes after deflate", encoding: []string{"deflate"}, wire: join(deflated, []byte("tail")), wantText: plain, want: map[string]string{ceeCodingRestStream: "tail"}},
		{name: "second gzip member is decoded", encoding: []string{"gzip"}, wire: join(gzipped, gzipRequestBody(t, second)), wantText: join(plain, second)},
		{name: "gzip header fields stay out of the text", encoding: []string{"gzip"}, wire: fielded, wantText: plain, want: map[string]string{ceeCodingFieldsStream: "name-fieldcomment-fieldextra-field"}},
		{name: "later member field does not split the text", encoding: []string{"gzip"}, wire: join(gzipped, laterFields), wantText: join(plain, second), want: map[string]string{ceeCodingFieldsStream: "later-comment"}},
		{name: "modification time of an empty member", encoding: []string{"gzip"}, wire: stamped, wantText: nil, want: map[string]string{ceeCodingStampStream: "abcd"}},
		{name: "modification times of two members", encoding: []string{"gzip"}, wire: join(stamped, laterStamp), wantText: second, want: map[string]string{ceeCodingStampStream: "abcdefgh"}},
		{name: "stream fails part way keeps the body as read", encoding: []string{"gzip"}, wire: truncated, wantText: nil, want: map[string]string{ceeCodingRestStream: string(truncated)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			for _, v := range tc.encoding {
				header.Add("Content-Encoding", v)
			}
			text, extras := ceeInspectedBody(header, tc.wire)
			if tc.name == "stream fails part way keeps the body as read" {
				if len(text) == 0 || !bytes.HasPrefix(plain, text) {
					t.Fatalf("text = %d bytes that are not a prefix of the plaintext", len(text))
				}
			} else if !bytes.Equal(text, tc.wantText) {
				t.Fatalf("text = %d bytes, want %d", len(text), len(tc.wantText))
			}
			if len(extras) != len(tc.want) {
				t.Fatalf("extras = %q, want %q", extras, tc.want)
			}
			for name, want := range tc.want {
				if string(extras[name]) != want {
					t.Fatalf("%s = %q, want %q", name, extras[name], want)
				}
			}
		})
	}
}

// A decoder can read ahead of the text it has returned. When decoding stops
// at the limit, the whole body as read stays inspected, so bytes the decoder
// consumed and never returned are not lost.
func TestCEEInspectedBodyKeepsWireWhenDecodingStopsAtLimit(t *testing.T) {
	stored := func(payload []byte) []byte {
		var buf bytes.Buffer
		zw, err := gzip.NewWriterLevel(&buf, gzip.NoCompression)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := zw.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	marker := []byte("marker-after-the-limit")
	first := gzipRequestBody(t, bytes.Repeat([]byte("A"), maxCEEBodyRead-16*1024))
	second := stored(append(bytes.Repeat([]byte("B"), 16*1024), marker...))
	wire := append(append([]byte{}, first...), second...)
	if len(wire) >= maxCEEBodyRead {
		t.Fatalf("fixture is %d bytes, want it under the read limit", len(wire))
	}
	text, extras := ceeInspectedBody(http.Header{"Content-Encoding": []string{"gzip"}}, wire)
	if len(text) != maxCEEBodyRead || bytes.Contains(text, marker) {
		t.Fatalf("text = %d bytes, marker in text = %v; the fixture should stop before the marker", len(text), bytes.Contains(text, marker))
	}
	if !bytes.Contains(extras[ceeCodingRestStream], marker) {
		t.Fatal("bytes after the limit were dropped from inspection")
	}
}

// A body that decodes to more than the read limit stops at the limit.
func TestCEEInspectedBodyBoundsDecodedText(t *testing.T) {
	wire := gzipRequestBody(t, bytes.Repeat([]byte("A"), maxCEEBodyRead*3))
	header := http.Header{"Content-Encoding": []string{"gzip"}}
	text, extras := ceeInspectedBody(header, wire)
	if len(text) != maxCEEBodyRead {
		t.Fatalf("text = %d bytes, want %d", len(text), maxCEEBodyRead)
	}
	if !bytes.Equal(extras[ceeCodingRestStream], wire) {
		t.Fatal("the body as read was not kept for inspection")
	}
}

// The decoded text is the scanned stream. Bytes a sender controls outside it
// become their own streams when fragments are reassembled, and join the one
// stream otherwise. The forwarded body is the bytes as read.
func TestExtractOutboundPayloadsSeparatesCodingExtras(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Header = gzip.Header{Comment: "comment-field"}
	if _, err := zw.Write([]byte("decoded part")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	wire := append(buf.Bytes(), []byte("plain tail")...)
	newRequest := func() *http.Request {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/upload", bytes.NewReader(wire))
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("Content-Type", "text/plain")
		return req
	}

	req := newRequest()
	got := extractOutboundPayloads(req, true, "session", []byte("partition-key"))
	if string(got.outbound) != "decoded part" {
		t.Fatalf("scanned stream = %q", got.outbound)
	}
	if string(got.bodyFragmentPayloads[ceeCodingFieldsStream]) != "comment-field" || string(got.bodyFragmentPayloads[ceeCodingRestStream]) != "plain tail" {
		t.Fatalf("side streams = %q", got.bodyFragmentPayloads)
	}
	if got.inspectionMode() != "raw" {
		t.Fatalf("inspection mode = %q, want raw for a body with no JSON partition", got.inspectionMode())
	}
	forwarded, err := io.ReadAll(req.Body)
	if err != nil || !bytes.Equal(forwarded, wire) {
		t.Fatalf("forwarded body changed: err=%v match=%v", err, bytes.Equal(forwarded, wire))
	}

	single := extractOutboundPayloads(newRequest(), false, "session", nil)
	if string(single.outbound) != "decoded partcomment-fieldplain tail" || len(single.bodyFragmentPayloads) != 0 {
		t.Fatalf("single stream = %q, side streams = %d", single.outbound, len(single.bodyFragmentPayloads))
	}
}

// A credential split across the same JSON field of two gzip requests, with
// unrelated padding in a sibling field, is joined by the JSON partition. Body
// scanning is off and request policy is the only other reader of the body, so
// the partition has to work from the decoded document.
func TestGzipJSONFieldSplitWithPolicyOnlyBodyRead(t *testing.T) {
	secret := testCEEAWSKeyPrefix + testCEEAWSKeySuffix
	half := len(secret) / 2
	padding := strings.Repeat("ordinary prose ", ceeForwardConversationPaddingBytes/len("ordinary prose "))
	configure := func(cfg *config.Config, host string) {
		rule := graphqlBlockRule()
		rule.Route.Hosts = []string{host}
		cfg.RequestPolicy.Enabled = true
		cfg.RequestPolicy.Rules = []config.RequestPolicyRule{rule}
		cfg.RequestBodyScanning.Enabled = false
		cfg.CrossRequestDetection = ceeFragmentBlockCfg()
		cfg.CrossRequestDetection.EntropyBudget.Enabled = false
		cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 2 * ceeForwardConversationPaddingBytes
		cfg.Taint.Enabled = false
	}
	// A benign GraphQL query keeps the policy rule from matching, so the
	// request is admitted and the policy still reads the body.
	document := func(content string) string {
		return `{"query":"query { id }","messages":[{"role":"user","content":"` + content + `"}],"history":"` + padding + `"}`
	}
	check := func(t *testing.T, send func(content string) *http.Response) {
		t.Helper()
		first := send(secret[:half])
		defer func() { _ = first.Body.Close() }()
		if first.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(first.Body)
			t.Fatalf("first status=%d body=%s", first.StatusCode, body)
		}
		second := send(secret[half:])
		defer func() { _ = second.Body.Close() }()
		if second.StatusCode != http.StatusForbidden || second.Header.Get(blockreason.HeaderLayer) != "cross_request" {
			body, _ := io.ReadAll(second.Body)
			t.Fatalf("second status=%d layer=%q body=%s", second.StatusCode, second.Header.Get(blockreason.HeaderLayer), body)
		}
	}

	t.Run("forward", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(backend.Close)
		proxyAddr, proxy, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
			configure(cfg, "api.example.com")
		})
		t.Cleanup(cleanup)
		installForwardTestDialer(proxy, backend.Listener.Addr().String())
		client := forwardHTTPClient(t, proxyAddr)
		check(t, func(content string) *http.Response {
			wire := gzipRequestBody(t, []byte(document(content)))
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.example.com/v1/messages", bytes.NewReader(wire))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Content-Encoding", "gzip")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			return resp
		})
	})

	t.Run("intercept", func(t *testing.T) {
		upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(upstream.Close)
		cache, pool, cfg, _, logger, m := testInterceptSetup(t)
		configure(cfg, upstream.Listener.Addr().(*net.TCPAddr).IP.String())
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		proxy, err := New(cfg, logger, sc, m)
		if err != nil {
			t.Fatalf("proxy: %v", err)
		}
		t.Cleanup(proxy.Close)
		check(t, func(content string) *http.Response {
			wire := gzipRequestBody(t, []byte(document(content)))
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+upstream.Listener.Addr().String()+"/v1/messages", bytes.NewReader(wire))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Content-Encoding", "gzip")
			return interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, proxy)
		})
	})
}

// A sender controls gzip header fields and how a body is cut into members.
// Neither may hide a credential split across two requests when body scanning
// is off: the decoded text of every member stays contiguous, and the header
// fields are reassembled as their own stream.
func TestGzipMembersAndFieldsDoNotHideSplitCredential(t *testing.T) {
	member := func(h gzip.Header, payload string) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Header = h
		if _, err := zw.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	cases := []struct {
		name string
		body func(part string) []byte
	}{
		{
			name: "comment between the halves",
			body: func(part string) []byte {
				return append(member(gzip.Header{}, ""), member(gzip.Header{Comment: "unrelated note"}, part)...)
			},
		},
		{
			name: "halves cut across members",
			body: func(part string) []byte {
				mid := len(part) / 2
				return append(member(gzip.Header{}, part[:mid]), member(gzip.Header{Name: "b.txt"}, part[mid:])...)
			},
		},
		{
			name: "halves carried in the comment",
			body: func(part string) []byte {
				return member(gzip.Header{Comment: part}, "ordinary text")
			},
		},
		{
			name: "halves carried in the comment of an empty body",
			body: func(part string) []byte {
				return member(gzip.Header{Comment: part}, "")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(backend.Close)
			proxyAddr, proxy, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = false
				cfg.CrossRequestDetection = ceeFragmentBlockCfg()
				cfg.Taint.Enabled = false
			})
			t.Cleanup(cleanup)
			installForwardTestDialer(proxy, backend.Listener.Addr().String())
			client := forwardHTTPClient(t, proxyAddr)
			send := func(part string) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.example.com/upload", bytes.NewReader(tc.body(part)))
				if err != nil {
					t.Fatalf("request: %v", err)
				}
				req.Header.Set("Content-Type", "text/plain")
				req.Header.Set("Content-Encoding", "gzip")
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("do: %v", err)
				}
				return resp
			}
			first := send(testCEEAWSKeyPrefix)
			defer func() { _ = first.Body.Close() }()
			if first.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(first.Body)
				t.Fatalf("first status=%d body=%s", first.StatusCode, body)
			}
			second := send(testCEEAWSKeySuffix)
			defer func() { _ = second.Body.Close() }()
			if second.StatusCode != http.StatusForbidden || second.Header.Get(blockreason.HeaderLayer) != "cross_request" {
				body, _ := io.ReadAll(second.Body)
				t.Fatalf("second status=%d layer=%q body=%s", second.StatusCode, second.Header.Get(blockreason.HeaderLayer), body)
			}
			if hits.Load() != 1 {
				t.Fatalf("upstream hits = %d, want only the first request", hits.Load())
			}
		})
	}
}

// The parts of a compressed body outside its decoded text count toward the
// entropy budget, including when the decoded text is empty and nothing else
// in the request carries data.
func TestCeeAdmitChargesCodingExtras(t *testing.T) {
	for _, stream := range ceeCodingStreams {
		t.Run(stream, func(t *testing.T) {
			et := scanner.NewEntropyTracker(1.0, 300)
			defer et.Close()
			logger, _ := audit.New("json", "stdout", "", false, false)
			cfg := config.CrossRequestDetection{
				EntropyBudget: config.CrossRequestEntropyBudget{
					Enabled: true, BitsPerWindow: 1.0, WindowMinutes: 5, Action: config.ActionBlock,
				},
			}
			result := ceeAdmit(t.Context(), ceeAdmitOptions{
				BodyFragmentPayloads: map[string][]byte{stream: []byte("data carried outside the decoded text")},
				TargetURL:            "http://api.vendor.example", Agent: testCEEAgent, ClientIP: testCEEClientIP, RequestID: testCEERequestID,
				Config: cfg, Entropy: et, Logger: logger, Metrics: metrics.New(),
			})
			if !result.Blocked || !result.EntropyHit {
				t.Fatalf("blocked=%v entropyHit=%v, want the entropy budget to refuse", result.Blocked, result.EntropyHit)
			}
		})
	}
}
