// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// The review fixes made on the forward and fetch paths apply equally to the
// intercepted entry point: nested SSRF refusal, the forwarded Host, the signed
// envelope, and the receipt shard.
func TestWatchInterceptCarriesAdmissionFixes(t *testing.T) {
	cfg := config.Defaults()
	cfg.WatchOnly = true
	cfg.Internal = nil
	cfg.TLSInterception.Enabled = true
	cfg.MediationEnvelope.Enabled = true
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.envelopeEmitterPtr.Store(envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash}))

	var hits atomic.Int32
	var host, mediation atomic.Value
	upstream := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		hits.Add(1)
		host.Store(r.Host)
		mediation.Store(r.Header.Get(envelope.HeaderName))
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})
	handler := newInterceptHandler(&InterceptContext{
		TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: audit.NewNop(),
		Metrics: p.metrics, Proxy: p, RequestID: "req-intercept",
	}, upstream)
	serve := func(target, hostHeader string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		req.Host = hostHeader
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	if w := serve("https://api.vendor.example/go"+watchNestedMetadataQuery, "api.vendor.example:443"); w.Code != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("nested SSRF reached the relay through intercept: status=%d hits=%d", w.Code, hits.Load())
	}
	if w := serve("https://api.vendor.example/data", "api.vendor.example"); w.Code != http.StatusOK {
		t.Fatalf("ordinary request refused: status=%d body=%s", w.Code, w.Body)
	}
	if got, _ := host.Load().(string); got != "api.vendor.example" {
		t.Fatalf("intercept rewrote an equivalent Host header: %q", got)
	}
	if got, _ := mediation.Load().(string); got == "" {
		t.Fatal("intercepted request left without a mediation envelope")
	}
}

// The reverse transport already signs and bounds its upstream, so the watch
// path only forwards the admission state and refuses a nested metadata
// destination in the relayed path.
func TestWatchReverseNestedSSRFRefusal(t *testing.T) {
	cfg := config.Defaults()
	cfg.WatchOnly = true
	cfg.Internal = nil
	var reached atomic.Bool
	srv := reverseTestSetup(t, cfg, func(w http.ResponseWriter, _ *http.Request) { reached.Store(true); w.WriteHeader(http.StatusOK) })
	resp, err := http.Get(srv.URL + "/go" + watchNestedMetadataQuery) //nolint:noctx // test server
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden || reached.Load() {
		t.Fatalf("nested SSRF reached the reverse upstream: status=%d reached=%v", resp.StatusCode, reached.Load())
	}
}

// A CONNECT to a guard-granted hostname that resolves to an internal address
// is dialed on the strength of its scan snapshot, as the forward path does.
func TestWatchConnectGrantedInternalDestinationDials(t *testing.T) {
	upstream := listenEcho(t)
	defer func() { _ = upstream.Close() }()
	port := upstream.Addr().(*net.TCPAddr).Port
	host := "guard.internal.example"

	cfg := config.Defaults()
	cfg.WatchOnly = true
	cfg.Internal = nil
	cfg.ForwardProxy.Enabled = true
	cfg.DNS.HostOverrides = map[string][]string{host: {"127.0.0.1"}}
	disabled := false
	cfg.ForwardProxy.SNIVerification = &disabled
	grantPort, err := destination.ParsePort(strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := destination.NewGrant(destination.NetworkTCP, host, grantPort)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := destination.NewGrantSet(grant)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := scanner.NewWithOptions(cfg, scanner.Options{DestinationGrants: grants})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		sc.Close()
		t.Fatal(err)
	}
	defer p.Close()
	server := httptest.NewServer(p.Handler())
	defer server.Close()
	conn := dialProxy(t, server.Listener.Addr().String())
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	authority := net.JoinHostPort(host, strconv.Itoa(port))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("granted CONNECT destination refused at the dial: status=%d", response.StatusCode)
	}
}
