// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/certgen"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const testTLSCRLBody = "compatibility-ok"

func TestTLSCRLDisabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	w := httptest.NewRecorder()
	p.buildHandler(p.buildMux()).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/pipelock/ca.crl", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestTLSCRLEnabled(t *testing.T) {
	cache, _, cfg, sc, logger, m := testInterceptSetup(t)
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.certCachePtr.Store(cache)
	w := httptest.NewRecorder()
	p.buildHandler(p.buildMux()).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/pipelock/ca.crl", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func newTLSCRLProxy(t *testing.T, mods ...func(*config.Config)) (*Proxy, *config.Config, *x509.Certificate) {
	t.Helper()
	ca, key, _, err := certgen.GenerateCA("Test", 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Listen = "127.0.0.1:0"
	cfg.TLSInterception.Enabled = true
	cfg.TLSInterception.CACertPath = filepath.Join(t.TempDir(), "ca.pem")
	cfg.TLSInterception.CAKeyPath = filepath.Join(t.TempDir(), "ca-key.pem")
	if err := certgen.SaveCA(cfg.TLSInterception.CACertPath, cfg.TLSInterception.CAKeyPath, ca, key); err != nil {
		t.Fatal(err)
	}
	for _, mod := range mods {
		mod(cfg)
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if err := p.LoadCertCache(cfg); err != nil {
		t.Fatal(err)
	}
	return p, cfg, ca
}

func TestTLSCRLResponse(t *testing.T) {
	p, _, ca := newTLSCRLProxy(t)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), method, tlsCRLPath, nil))
			if method == http.MethodPost {
				if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
					t.Fatalf("response = %v", w)
				}
				return
			}
			if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/pkix-crl" || w.Header().Get("Cache-Control") != "public, max-age=3600" {
				t.Fatalf("response = %v", w)
			}
			if method == http.MethodHead {
				if w.Body.Len() != 0 {
					t.Fatal("HEAD body")
				}
				return
			}
			crl, err := x509.ParseRevocationList(w.Body.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if err := crl.CheckSignatureFrom(ca); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTLSCRLReload(t *testing.T) {
	p, cfg, _ := newTLSCRLProxy(t)
	p.SetTLSCRLBoundAddress("127.0.0.1:12345")
	original := p.certCachePtr.Load()
	first, err := original.CRL()
	if err != nil {
		t.Fatal(err)
	}
	reload := func(next *config.Config) {
		t.Helper()
		snapshot := *next
		sc := scanner.MustNew(&snapshot)
		t.Cleanup(sc.Close)
		if !p.Reload(&snapshot, sc) {
			t.Fatal("reload rejected")
		}
		if err := p.LoadCertCache(&snapshot); err != nil {
			t.Fatal(err)
		}
	}
	leafCDP := func(want string) {
		t.Helper()
		leaf, err := p.certCachePtr.Load().Get("api.vendor.example")
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(leaf.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if want == "" {
			if len(parsed.CRLDistributionPoints) != 0 {
				t.Fatal(parsed.CRLDistributionPoints)
			}
			return
		}
		if len(parsed.CRLDistributionPoints) != 1 || parsed.CRLDistributionPoints[0] != want {
			t.Fatal(parsed.CRLDistributionPoints)
		}
	}
	leafCDP("http://127.0.0.1:12345" + tlsCRLPath)
	next := *cfg
	next.FetchProxy.TimeoutSeconds++
	reload(&next)
	if p.certCachePtr.Load() != original {
		t.Fatal("unrelated reload replaced cache")
	}
	second, err := original.CRL()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("unrelated reload replaced CRL")
	}
	next.TLSInterception.CRLURL = "http://crl.vendor.example/ca.crl"
	reload(&next)
	leafCDP(next.TLSInterception.CRLURL)
	next.TLSInterception.CRLURL = "off"
	reload(&next)
	leafCDP("")
	next.TLSInterception.CRLURL = ""
	reload(&next)
	leafCDP("http://127.0.0.1:12345" + tlsCRLPath)
	// Replacing the CA at the same filenames must install a new issuer/cache.
	ca, key, _, err := certgen.GenerateCA("Replacement", 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := certgen.SaveCAForce(next.TLSInterception.CACertPath, next.TLSInterception.CAKeyPath, ca, key); err != nil {
		t.Fatal(err)
	}
	reload(&next)
	replaced := p.certCachePtr.Load()
	if replaced == original {
		t.Fatal("CA change retained old cache")
	}
	der, err := replaced.CRL()
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	next.TLSInterception.Enabled = false
	reload(&next)
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tlsCRLPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatal(w.Code)
	}
	next.TLSInterception.Enabled = true
	reload(&next)
	leafCDP("http://127.0.0.1:12345" + tlsCRLPath)
}

func TestTLSCRLBoundListener(t *testing.T) {
	p, _, _ := newTLSCRLProxy(t)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- p.StartWithListener(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("shutdown timed out")
		}
	})
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Do(tlsCRLClientRequest(t, "http://"+ln.Addr().String()+tlsCRLPath))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	leaf, err := p.certCachePtr.Load().Get("api.vendor.example")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.CRLDistributionPoints) != 1 || parsed.CRLDistributionPoints[0] != "http://"+ln.Addr().String()+tlsCRLPath {
		t.Fatal(parsed.CRLDistributionPoints)
	}
	// A proxy-configured client sends absolute-form requests for the CRL.
	proxyURL, err := url.Parse("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	proxyClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	defer proxyClient.CloseIdleConnections()
	absolute, err := proxyClient.Do(tlsCRLClientRequest(t, proxyURL.String()+tlsCRLPath))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = absolute.Body.Close() }()
	if absolute.StatusCode != http.StatusOK {
		t.Fatal(absolute.StatusCode)
	}
}

func TestTLSCRLSelfTargetScope(t *testing.T) {
	p, _, _ := newTLSCRLProxy(t)
	p.SetTLSCRLBoundAddress("127.0.0.1:12345")
	for _, target := range []string{
		"http://127.0.0.1:12345/health", "http://127.0.0.1:12346" + tlsCRLPath,
		"http://127.0.0.2:12345" + tlsCRLPath, "http://localhost:12345" + tlsCRLPath,
		"https://127.0.0.1:12345" + tlsCRLPath, "http://127.0.0.1:12345" + tlsCRLPath + "?x=y",
		"http://127.0.0.1:12345/.well-known/pipelock/%63a.crl", "http://api.vendor.example:12345" + tlsCRLPath,
		"http://user@127.0.0.1:12345" + tlsCRLPath,
	} {
		t.Run(target, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			if p.isSelfCRLRequest(r) {
				t.Fatal("unexpected local route")
			}
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, r)
			if w.Code == http.StatusOK {
				t.Fatal("unrelated request served locally")
			}
		})
	}
	for _, addr := range []string{"0.0.0.0:12345", "[::]:12345", "[::1]:12345"} {
		p.SetTLSCRLBoundAddress(addr)
		host := "127.0.0.1:12345"
		if addr == "[::1]:12345" {
			host = addr
		}
		if !p.isSelfCRLRequest(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+host+tlsCRLPath, nil)) {
			t.Fatal("loopback route refused", addr)
		}
	}
}

func TestTLSCRLUnboundSelfTarget(t *testing.T) {
	p := &Proxy{}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:12345"+tlsCRLPath, nil)
	for _, addr := range []string{"", "bad", "127.0.0.1:0", "localhost:12345"} {
		p.tlsCRLAddr = addr
		if p.isSelfCRLRequest(req) {
			t.Fatalf("invalid listener %q accepted", addr)
		}
	}
	p.tlsCRLAddr = "127.0.0.1:80"
	if !p.isSelfCRLRequest(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1"+tlsCRLPath, nil)) {
		t.Fatal("implicit HTTP port refused")
	}
}

func TestTLSCRLDefaultURL(t *testing.T) {
	for _, tc := range []struct{ addr, want string }{
		{"0.0.0.0:8888", "http://127.0.0.1:8888" + tlsCRLPath},
		{"[::]:8888", "http://127.0.0.1:8888" + tlsCRLPath},
		{":8888", "http://127.0.0.1:8888" + tlsCRLPath},
		{"[::1]:8888", "http://[::1]:8888" + tlsCRLPath},
		{"127.0.0.1:0", ""},
		{"bad", ""},
		{"api.vendor.example:8888", "http://api.vendor.example:8888" + tlsCRLPath},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			if got := defaultTLSCRLURL(tc.addr); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTLSCRLFailureAndWarning(t *testing.T) {
	p, _, ca := newTLSCRLProxy(t)
	// A signer failure must return an error response, never unsigned CRL bytes.
	bad, err := certgen.NewCertCache(ca, struct{}{}, time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	p.certCachePtr.Store(bad)
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tlsCRLPath, nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal(w.Code)
	}
	var log bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, &log)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	p.logger = logger
	ca.KeyUsage &^= x509.KeyUsageCRLSign
	noSign, err := certgen.NewCertCache(ca, struct{}{}, time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	p.certCachePtr.Store(noSign)
	p.SetTLSCRLBoundAddress("127.0.0.1:12345")
	p.SetTLSCRLBoundAddress("127.0.0.1:12345")
	if strings.Count(log.String(), "lacks CRL signing usage") != 1 || !strings.Contains(log.String(), `"level":"warn"`) {
		t.Fatalf("warning = %s", log.String())
	}
	w = httptest.NewRecorder()
	p.Handler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tlsCRLPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatal(w.Code)
	}
}

func TestTLSCRLHTTPSClient(t *testing.T) { testTLSCRLHTTPSClient(t, false) }

func TestWindowsTLSCRLSchannel(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("requires native Windows Schannel")
	}
	testTLSCRLHTTPSClient(t, true)
}

func testTLSCRLHTTPSClient(t *testing.T, schannel bool) {
	t.Helper()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, testTLSCRLBody) }))
	defer upstream.Close()
	p, cfg, ca := newTLSCRLProxy(t, func(c *config.Config) {
		c.ForwardProxy.Enabled = true
		c.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	})
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	p.tlsTransport.CloseIdleConnections()
	p.tlsTransport = newTLSInterceptTransport(p.ssrfSafeDialContext, p.metrics.RecordTLSHandshake, roots)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- p.StartWithListener(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("shutdown timed out")
		}
	})
	proxyURL, err := url.Parse("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if schannel {
		// Select the built-in client even if Git's OpenSSL curl precedes it on PATH.
		curl := filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe")
		version, err := exec.CommandContext(t.Context(), curl, "--version").CombinedOutput() // #nosec G204 G702 -- the Windows-only test runs the built-in curl under SystemRoot.
		if err != nil || !strings.Contains(strings.ToLower(string(version)), "schannel") {
			t.Fatalf("native Schannel curl unavailable: %v: %s", err, version)
		}
		output, err := exec.CommandContext(t.Context(), curl, "--silent", "--show-error", "--fail", "--max-time", "15", "--noproxy", "", "--proxy", proxyURL.String(), "--cacert", cfg.TLSInterception.CACertPath, upstream.URL).CombinedOutput() // #nosec G204 G702 -- the Windows-only test runs the built-in curl under SystemRoot.
		if err != nil || string(output) != testTLSCRLBody {
			t.Fatalf("Schannel HTTPS request: %v: %s", err, output)
		}
		return
	}
	trust := x509.NewCertPool()
	trust.AddCert(ca)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS12}}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Do(tlsCRLClientRequest(t, upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != testTLSCRLBody {
		t.Fatalf("HTTPS response: %v: %s", err, body)
	}
}

func tlsCRLClientRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func BenchmarkTLSCRLRequestClassification(b *testing.B) {
	p := &Proxy{}
	req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "http://api.vendor.example/v1/messages", nil)
	b.ReportAllocs()
	for b.Loop() {
		if p.isSelfCRLRequest(req) {
			b.Fatal("unexpected local route")
		}
	}
}

func TestTLSCRLKillSwitch(t *testing.T) {
	p, cfg, _ := newTLSCRLProxy(t)
	p.SetTLSCRLBoundAddress("127.0.0.1:12345")
	p.ks = killswitch.New(cfg)
	p.ks.SetAPI(true)
	for _, target := range []string{tlsCRLPath, "http://127.0.0.1:12345" + tlsCRLPath} {
		w := httptest.NewRecorder()
		p.Handler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
		if w.Code != http.StatusServiceUnavailable && w.Code != http.StatusForbidden {
			t.Fatalf("kill switch status = %d", w.Code)
		}
		if w.Header().Get("Content-Type") == "application/pkix-crl" {
			t.Fatal("kill switch served CRL")
		}
	}
}
