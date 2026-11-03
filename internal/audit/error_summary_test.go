// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

type auditUnformattableError struct{ child error }

func (auditUnformattableError) Error() string   { panic("URL-bearing error text must not be formatted") }
func (e auditUnformattableError) Unwrap() error { return e.child }

func TestAuditURLErrorUsesTypedPartsOnly(t *testing.T) {
	raw := "https://api.vendor.example/payloadcanary?" + url.Values{"token": {"payloadcanary"}}.Encode()
	leaf := &url.Error{Op: "Get", URL: raw, Err: errors.New("cause payloadcanary")}
	var shared error = leaf
	for range 60 {
		shared = errors.Join(shared, shared)
	}
	for name, err := range map[string]error{
		"cause":                 leaf,
		"shared tree":           shared,
		"noncomparable leaf":    &url.Error{Op: "Get", URL: raw, Err: auditValueError{1}},
		"repeated diagnostics":  errors.Join(leaf, &net.OpError{Op: "dial", Net: "tcp", Err: io.EOF}, &net.OpError{Op: "dial", Net: "tcp", Err: io.EOF}),
		"wrapper":               fmt.Errorf("wrapper payloadcanary: %w", leaf),
		"sibling":               errors.Join(leaf, errors.New("sibling payloadcanary")),
		"operation":             &url.Error{Op: "payloadcanary", URL: raw, Err: errors.New("failure")},
		"unformattable wrapper": auditUnformattableError{leaf},
		"unformattable cause":   &url.Error{Op: "Get", URL: raw, Err: auditUnformattableError{}},
	} {
		t.Run(name, func(t *testing.T) {
			got := redactURLErrors(err).Error()
			if strings.Contains(got, "payloadcanary") {
				t.Fatalf("raw error text reached summary: %q", got)
			}
			if !strings.Contains(got, "https://api.vendor.example") {
				t.Fatalf("missing safe destination: %q", got)
			}
		})
	}
}

func TestAuditHTTPUnsupportedScheme(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "payloadcanary://api.vendor.example/private?"+url.Values{"token": {"payloadcanary"}}.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(req)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil {
		t.Fatal("expected unsupported scheme error")
	}
	got := redactURLErrors(err).Error()
	t.Logf("producer=%q audit=%q", err, got)
	if strings.Contains(got, "payloadcanary") {
		t.Fatalf("unsupported scheme echoed input: %q", got)
	}
}

// These values use the public error fields, including hostile text in every
// free-form field that must never reach the audit diagnostic.
func TestAuditURLErrorCategories(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"canceled", context.Canceled, "context canceled"},
		{"deadline", context.DeadlineExceeded, "deadline exceeded"},
		{"EOF", io.EOF, "EOF"},
		{"unexpected EOF", io.ErrUnexpectedEOF, "unexpected EOF"},
		{"refused", syscall.ECONNREFUSED, "connection refused"},
		{"reset", syscall.ECONNRESET, "connection reset"},
		{"pipe", syscall.EPIPE, "broken pipe"},
		{"network", syscall.ENETUNREACH, "network unreachable"},
		{"host", syscall.EHOSTUNREACH, "host unreachable"},
		{"dial", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("payloadcanary")}, "dial tcp failed"},
		{"custom dial", &net.OpError{Op: "payloadcanary", Net: "payloadcanary", Err: errors.New("payloadcanary")}, "network operation network failed"},
		{"DNS timeout", &net.DNSError{Err: "payloadcanary", Name: "payloadcanary", Server: "payloadcanary", IsTimeout: true}, "DNS timeout"},
		{"DNS not found", &net.DNSError{Err: "payloadcanary", Name: "payloadcanary", IsNotFound: true}, "DNS name not found"},
		{"DNS temporary", &net.DNSError{Err: "payloadcanary", IsTemporary: true}, "DNS temporary failure"},
		{"DNS unknown", &net.DNSError{Err: "payloadcanary"}, "DNS lookup failed"},
		{"TLS record", tls.RecordHeaderError{Msg: "payloadcanary"}, "TLS record header error"},
		{"TLS cert", &tls.CertificateVerificationError{Err: errors.New("payloadcanary")}, "TLS certificate verification failed"},
		{"TLS authority", x509.UnknownAuthorityError{}, "TLS unknown certificate authority"},
		{"TLS hostname", x509.HostnameError{Host: "payloadcanary"}, "TLS certificate hostname mismatch"},
		{"TLS invalid", x509.CertificateInvalidError{Detail: "payloadcanary"}, "TLS certificate invalid"},
		{"TLS roots", x509.SystemRootsError{Err: errors.New("payloadcanary")}, "TLS system roots unavailable"},
		{"TLS alert", tls.AlertError(42), "TLS alert 42"},
		{"HTTP2", http2.StreamError{Code: http2.ErrCodeCancel, Cause: errors.New("payloadcanary")}, "HTTP/2 stream error code 8"},
		{"unknown", auditUnformattableError{}, "request failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := redactURLErrors(&url.Error{Op: "Get", URL: "https://api.vendor.example/payloadcanary", Err: tt.err}).Error()
			if !strings.Contains(got, tt.want) || strings.Contains(got, "payloadcanary") {
				t.Fatalf("got %q, want %q without raw text", got, tt.want)
			}
		})
	}
}

func TestAuditHTTPErrorDiagnostics(t *testing.T) {
	for _, name := range []string{"connection refused", "canceled", "deadline", "client timeout", "TLS authority", "TLS hostname", "HTTPS to HTTP", "HTTP2 stdlib", "EOF", "redirect loop"} {
		t.Run(name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch name {
				case "client timeout":
					<-r.Context().Done()
				case "HTTP2 stdlib":
					panic(http.ErrAbortHandler)
				case "EOF":
					h, ok := w.(http.Hijacker)
					if !ok {
						t.Error("hijacking unsupported")
						return
					}
					conn, _, err := h.Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
				case "redirect loop":
					w.Header().Set("Location", "/payloadcanary")
					w.WriteHeader(http.StatusFound)
				}
			})
			ts := httptest.NewUnstartedServer(handler)
			ts.Config.ErrorLog = log.New(io.Discard, "", 0)
			tlsServer := strings.HasPrefix(name, "TLS ") || strings.HasPrefix(name, "HTTP2 ")
			ts.EnableHTTP2 = strings.HasPrefix(name, "HTTP2 ")
			if tlsServer {
				ts.StartTLS()
			} else {
				ts.Start()
			}
			defer ts.Close()
			client := ts.Client()
			client.Timeout = 2 * time.Second
			target := ts.URL + "/payloadcanary?" + url.Values{"token": {"payloadcanary"}}.Encode()
			ctx := t.Context()
			want := "request failed"
			switch name {
			case "connection refused":
				addr := ts.Listener.Addr().String()
				ts.Close()
				target = "http://" + addr + "/payloadcanary"
				want = "connection refused"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = "context canceled"
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Unix(0, 0))
				defer cancel()
				want = "deadline exceeded"
			case "client timeout":
				client.Timeout = 100 * time.Millisecond
				want = "timeout"
			case "TLS authority":
				transport := &http.Transport{}
				defer transport.CloseIdleConnections()
				client = &http.Client{Transport: transport, Timeout: 2 * time.Second}
				want = "TLS unknown certificate authority"
			case "TLS hostname":
				target = strings.Replace(target, "127.0.0.1", "localhost", 1)
				want = "TLS certificate hostname mismatch"
			case "HTTPS to HTTP":
				target = strings.Replace(target, "http:", "https:", 1)
			case "EOF":
				want = "EOF"
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if err == nil {
				t.Fatal("expected HTTP producer error")
			}
			got := redactURLErrors(err).Error()
			t.Logf("producer=%q audit=%q", err, got)
			if strings.Contains(got, "payloadcanary") || !strings.Contains(got, want) {
				t.Errorf("got %q, want %q without request content", got, want)
			}
		})
	}
}

type auditNonURLTimeoutError struct{}

func (auditNonURLTimeoutError) Error() string { return "ordinary failure" }
func (auditNonURLTimeoutError) Timeout() bool { panic("non-URL error must not be classified") }

func TestAuditNonURLErrorPreserved(t *testing.T) {
	err := auditNonURLTimeoutError{}
	if got := redactURLErrors(err); !sameError(got, err) {
		t.Fatalf("non-URL error changed: %v", got)
	}
}
