// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestIssuedLocationCanonical(t *testing.T) {
	t.Parallel()
	canon := func(raw string) string {
		t.Helper()
		got, ok := issuedLocationCanonical(mustIssuerQueryURL(t, raw))
		if !ok {
			t.Fatalf("%q has no identity", raw)
		}
		return got
	}
	same := [][2]string{
		{"https://files.vendor.example/a?x=1&y=2", "https://FILES.vendor.example:443/a?y=2&x=1"},
		{"https://files.vendor.example./a?x=1", "https://files.vendor.example/a?x=1"},
		{"https://files.vendor.example/a?x=1&x=2", "https://files.vendor.example/a?x=2&x=1"},
		{"https://files.vendor.example/a", "https://files.vendor.example/a#fragment"},
		{"https://bücher.vendor.example/a", "https://xn--bcher-kva.vendor.example/a"},
		{"https://files.vendor.example/a?x=%41", "https://files.vendor.example/a?x=A"},
	}
	for _, pair := range same {
		if canon(pair[0]) != canon(pair[1]) {
			t.Errorf("%q and %q should be one identity", pair[0], pair[1])
		}
	}
	different := [][2]string{
		{"https://files.vendor.example/a?x=1", "https://files.vendor.example/a?x=2"},
		{"https://files.vendor.example/a?x=1", "https://files.vendor.example/a?x=1&x=1"},
		{"https://files.vendor.example/a?x=1&x=2", "https://files.vendor.example/a?x=1"},
		{"https://files.vendor.example/a?x=1", "https://files.vendor.example/a?y=1"},
		{"https://files.vendor.example/a", "https://files.vendor.example/a/"},
		{"https://files.vendor.example/a%2Fb", "https://files.vendor.example/a/b"},
		{"https://files.vendor.example/a", "https://files.vendor.example:8443/a"},
		{"https://files.vendor.example/a", "https://other.vendor.example/a"},
		{"https://files.vendor.example/a?x=1", "https://files.vendor.example/a"},
	}
	for _, pair := range different {
		if canon(pair[0]) == canon(pair[1]) {
			t.Errorf("%q and %q must be different identities", pair[0], pair[1])
		}
	}
	// The key and value are separate fields: moving a character across the
	// boundary is a different multiset.
	if canon("https://files.vendor.example/a?ab=c") == canon("https://files.vendor.example/a?a=bc") {
		t.Error("key/value boundary was not preserved")
	}
	for _, raw := range []string{
		"http://files.vendor.example/a",          // not https
		"https://u:p@files.vendor.example/a",     // userinfo
		"https://files.vendor.example/a?x=1;y=2", // ambiguous separator
		"https://files.vendor.example/a?x=%zz",   // malformed escape
		"mailto:a@vendor.example",                // opaque
	} {
		if _, ok := issuedLocationCanonical(mustIssuerQueryURL(t, raw)); ok {
			t.Errorf("%q must have no identity", raw)
		}
	}
	if _, ok := issuedLocationCanonical(nil); ok {
		t.Error("nil URL has an identity")
	}
}

func TestCanonicalRedirectHost(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"Files.Vendor.Example.":        "files.vendor.example",
		"bücher.vendor.example":        "xn--bcher-kva.vendor.example",
		"XN--BCHER-KVA.vendor.example": "xn--bcher-kva.vendor.example",
		"2001:db8::1":                  "2001:db8::1",
		"10.0.0.1":                     "10.0.0.1",
		"":                             "",
		"bad_host\x00.example":         "bad_host\x00.example", // a failed lookup keeps the input
	} {
		if got := canonicalRedirectHost(in); got != want {
			t.Errorf("canonicalRedirectHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func delegationTestStore(t *testing.T) *issuerQueryStore {
	t.Helper()
	s := newIssuerQueryStore()
	if s.disabled {
		t.Fatal("store disabled")
	}
	return s
}

func TestIssuedLocationStoreBinding(t *testing.T) {
	t.Parallel()
	s := delegationTestStore(t)
	target := mustIssuerQueryURL(t, delegationFilesURL(delegationFilesPath, delegationTicketQuery()))
	scope := [32]byte{1}
	other := [32]byte{2}
	live := map[[32]byte]struct{}{scope: {}}
	now := time.Now()

	s.rememberIssuedLocation("session-a", target, scope, now)
	s.rememberIssuedLocation("session-a", target, scope, now) // idempotent
	if got := len(s.locations["session-a"]); got != 1 {
		t.Fatalf("duplicate mint stored %d entries", got)
	}
	if !s.issuedLocation("session-a", target, live) {
		t.Fatal("minted URL not found")
	}
	if s.issuedLocation("session-b", target, live) {
		t.Fatal("another session sees the evidence")
	}
	if s.issuedLocation("session-a", target, map[[32]byte]struct{}{other: {}}) {
		t.Fatal("evidence honored under a scope that is not in force")
	}
	if s.issuedLocation("session-a", target, nil) || s.issuedLocation("session-a", target, map[[32]byte]struct{}{}) {
		t.Fatal("evidence honored with no delegation in force")
	}
	if s.issuedLocation("", target, live) {
		t.Fatal("empty session matched")
	}
	if s.issuedLocation("session-a", mustIssuerQueryURL(t, "http://files.vendor.example/x"), live) {
		t.Fatal("non-https URL matched")
	}
	if s.issuedLocation("session-a", mustIssuerQueryURL(t, "https://files.vendor.example/x?a=b;c"), live) {
		t.Fatal("unparseable query matched")
	}
	// The same URL under a second delegation is separate evidence.
	s.rememberIssuedLocation("session-a", target, other, now)
	if got := len(s.locations["session-a"]); got != 2 {
		t.Fatalf("entries = %d, want 2", got)
	}
	// An authority hit is not a URL hit.
	if !s.issuedAuthority("session-a", delegationFilesHost, "443", live) {
		t.Fatal("authority evidence missing")
	}
	if s.issuedAuthority("session-a", delegationFilesHost, "8443", live) || s.issuedAuthority("session-a", "other.vendor.example", "443", live) ||
		s.issuedAuthority("session-b", delegationFilesHost, "443", live) || s.issuedAuthority("session-a", delegationFilesHost, "443", nil) ||
		s.issuedAuthority("", delegationFilesHost, "443", live) || s.issuedAuthority("session-a", "", "443", live) || s.issuedAuthority("session-a", delegationFilesHost, "", live) {
		t.Fatal("authority evidence leaked across a boundary")
	}
	if !s.issuedAuthority("session-a", "FILES.vendor.example.", "443", live) {
		t.Fatal("authority lookup does not canonicalize the host")
	}
	if s.issuedLocation("session-a", mustIssuerQueryURL(t, delegationFilesURL(delegationFilesPath, "tempauth=other")), live) {
		t.Fatal("authority evidence admitted a different URL")
	}
}

func TestIssuedLocationStoreIsBoundedAndSessionScoped(t *testing.T) {
	t.Parallel()
	s := delegationTestStore(t)
	scope := [32]byte{1}
	live := map[[32]byte]struct{}{scope: {}}
	now := time.Now()
	url := func(i int) *url.URL {
		return mustIssuerQueryURL(t, fmt.Sprintf("https://files.vendor.example/d/%d?k=v", i))
	}
	for i := 0; i < issuerCookieMaxEntries+5; i++ {
		s.rememberIssuedLocation("session-a", url(i), scope, now)
	}
	if got := len(s.locations["session-a"]); got != issuerCookieMaxEntries {
		t.Fatalf("entries = %d, want the %d bound", got, issuerCookieMaxEntries)
	}
	if s.issuedLocation("session-a", url(0), live) {
		t.Fatal("oldest entry survived eviction: it must return to ordinary scanning")
	}
	if !s.issuedLocation("session-a", url(issuerCookieMaxEntries+4), live) {
		t.Fatal("newest entry missing")
	}

	// Session capacity: admitting a session past the cap evicts the least
	// recently used one, evidence included.
	for i := 0; i < issuerCookieMaxSessions; i++ {
		s.rememberIssuedLocation(fmt.Sprintf("s-%02d", i), url(1), scope, time.Now().Add(time.Hour+time.Duration(i)*time.Second))
	}
	if _, kept := s.locations["session-a"]; kept {
		t.Fatal("the least recently used session kept its evidence past the session cap")
	}
	if len(s.used) > issuerCookieMaxSessions {
		t.Fatalf("sessions = %d, want at most %d", len(s.used), issuerCookieMaxSessions)
	}
}

func TestIssuedLocationStoreFailsClosed(t *testing.T) {
	t.Parallel()
	var nilStore *issuerQueryStore
	target := mustIssuerQueryURL(t, delegationFilesURL(delegationFilesPath, "a=b"))
	live := map[[32]byte]struct{}{{1}: {}}
	nilStore.rememberIssuedLocation("s", target, [32]byte{1}, time.Now())
	if nilStore.issuedLocation("s", target, live) || nilStore.issuedAuthority("s", delegationFilesHost, "443", live) {
		t.Fatal("nil store matched")
	}
	failing := newIssuerQueryStoreWithReader(strings.NewReader("short")) // not enough entropy for the key
	if !failing.disabled {
		t.Fatal("store with no key must be disabled")
	}
	failing.rememberIssuedLocation("s", target, [32]byte{1}, time.Now())
	if len(failing.locations) != 0 || failing.issuedLocation("s", target, live) || failing.issuedAuthority("s", delegationFilesHost, "443", live) {
		t.Fatal("disabled store minted or matched")
	}
	s := delegationTestStore(t)
	s.rememberIssuedLocation("s", mustIssuerQueryURL(t, "http://files.vendor.example/a"), [32]byte{1}, time.Now())
	s.rememberIssuedLocation("", target, [32]byte{1}, time.Now())
	if len(s.locations) != 0 {
		t.Fatal("an unmintable target or empty session stored evidence")
	}
	// A restart is a new store with a new key: nothing carries over.
	s.rememberIssuedLocation("s", target, [32]byte{1}, time.Now())
	restarted := newIssuerQueryStoreWithReader(rand.Reader)
	if restarted.issuedLocation("s", target, live) {
		t.Fatal("evidence survived a restart")
	}
}

func TestIssuedLocationStoreConcurrent(t *testing.T) {
	t.Parallel()
	s := delegationTestStore(t)
	scope := [32]byte{7}
	live := map[[32]byte]struct{}{scope: {}}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				target, _ := url.Parse(fmt.Sprintf("https://files.vendor.example/d/%d?k=%d", i%50, w))
				session := fmt.Sprintf("s-%d", i%40) // exceeds the session cap to exercise eviction
				s.rememberIssuedLocation(session, target, scope, time.Now())
				s.issuedLocation(session, target, live)
				s.issuedAuthority(session, delegationFilesHost, "443", live)
			}
		}()
	}
	wg.Wait()
}

func TestIssuedRedirectLocation(t *testing.T) {
	t.Parallel()
	source := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.vendor.example/v1/items/42/content?select=a", nil)
	// locate builds a synthetic response and releases it before returning.
	locate := func(status, maxLen int, locations ...string) (*url.URL, bool) {
		h := http.Header{}
		for _, l := range locations {
			h.Add("Location", l)
		}
		r := &http.Response{StatusCode: status, Header: h, Request: source, Body: http.NoBody}
		defer func() { _ = r.Body.Close() }()
		return issuedRedirectLocation(r, maxLen)
	}
	got, ok := locate(http.StatusFound, 0, "/dl/a?x=1#f")
	if !ok || got.String() != "https://api.vendor.example/dl/a?x=1" {
		t.Fatalf("relative Location = %v, %v", got, ok)
	}
	if got, ok := locate(http.StatusTemporaryRedirect, 0, "https://files.vendor.example/a"); !ok || got.Host != "files.vendor.example" {
		t.Fatalf("absolute Location = %v, %v", got, ok)
	}
	tooLong := "https://files.vendor.example/" + strings.Repeat("a", 100)
	if _, ok := locate(http.StatusFound, 50, tooLong); ok {
		t.Fatal("a Location past the URL length limit was minted")
	}
	if _, ok := locate(http.StatusFound, 0, tooLong); !ok {
		t.Fatal("a zero limit means no limit, as in the scanner")
	}
	if _, ok := issuedRedirectLocation(nil, 0); ok {
		t.Error("nil response: minted")
	}
	for name, h := range map[string]*http.Response{
		"no request":     {StatusCode: http.StatusFound, Header: http.Header{"Location": {"/a"}}, Body: http.NoBody},
		"no request URL": {StatusCode: http.StatusFound, Header: http.Header{"Location": {"/a"}}, Request: &http.Request{}, Body: http.NoBody},
	} {
		if _, ok := issuedRedirectLocation(h, 0); ok {
			t.Errorf("%s: minted", name)
		}
		_ = h.Body.Close()
	}
	for _, tc := range []struct {
		name      string
		status    int
		locations []string
	}{
		{"304", http.StatusNotModified, []string{"/a"}},
		{"300", http.StatusMultipleChoices, []string{"/a"}},
		{"305", http.StatusUseProxy, []string{"/a"}},
		{"201", http.StatusCreated, []string{"/a"}},
		{"200", http.StatusOK, []string{"/a"}},
		{"no Location", http.StatusFound, nil},
		{"empty Location", http.StatusFound, []string{""}},
		{"two Locations", http.StatusFound, []string{"/a", "/b"}},
		{"control byte", http.StatusFound, []string{"/a\x01b"}},
		{"space", http.StatusFound, []string{"/a b"}},
		{"backslash", http.StatusFound, []string{`\evil.example`}},
		{"unparseable", http.StatusFound, []string{"http://[::1"}},
	} {
		if _, ok := locate(tc.status, 0, tc.locations...); ok {
			t.Errorf("%s: minted", tc.name)
		}
	}
}

func TestIssuedRedirectDelegationAdmits(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.FetchProxy.Monitoring.IssuedRedirectDelegations = []config.IssuedRedirectDelegation{delegationFixture()}
	delegations := compileIssuedRedirectDelegations(cfg, time.Now())
	if len(delegations) != 1 {
		t.Fatalf("compiled %d delegations", len(delegations))
	}
	d := delegations[0]
	files := mustIssuerQueryURL(t, delegationFilesURL(delegationFilesPath, "a=b"))
	req := func(method, raw string) *http.Request {
		return httptest.NewRequestWithContext(context.Background(), method, raw, nil)
	}
	if !d.admits(req(http.MethodGet, delegationSourceURL()), files) {
		t.Fatal("declared route not admitted")
	}
	if !d.admits(req(http.MethodGet, delegationSourceURL()+"?select=x"), files) {
		t.Fatal("the source query is not part of the route")
	}
	for name, tc := range map[string]struct {
		source *http.Request
		target *url.URL
	}{
		"nil source":      {nil, files},
		"nil source URL":  {&http.Request{}, files},
		"wrong method":    {req(http.MethodPost, delegationSourceURL()), files},
		"wrong path":      {req(http.MethodGet, "https://api.vendor.example/v2/items/42/content"), files},
		"prefix sibling":  {req(http.MethodGet, "https://api.vendor.example/v1/itemsx"), files},
		"other host":      {req(http.MethodGet, "https://other.vendor.example"+delegationSourcePath), files},
		"subdomain host":  {req(http.MethodGet, "https://a.api.vendor.example"+delegationSourcePath), files},
		"plaintext":       {req(http.MethodGet, "http://api.vendor.example"+delegationSourcePath), files},
		"other port":      {req(http.MethodGet, "https://api.vendor.example:8443"+delegationSourcePath), files},
		"dot segments":    {req(http.MethodGet, "https://api.vendor.example/v1/items/../../v2/x"), files},
		"unlisted origin": {req(http.MethodGet, delegationSourceURL()), mustIssuerQueryURL(t, "https://other.vendor.example/a")},
		"target port":     {req(http.MethodGet, delegationSourceURL()), mustIssuerQueryURL(t, "https://files.vendor.example:8443/a")},
		"target http":     {req(http.MethodGet, delegationSourceURL()), mustIssuerQueryURL(t, "http://files.vendor.example/a")},
	} {
		if d.admits(tc.source, tc.target) {
			t.Errorf("%s: admitted", name)
		}
	}
}

func TestIssuedRedirectsRequireSnapshotAndLivePolicy(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.IssuedRedirectDelegations = []config.IssuedRedirectDelegation{delegationFixture()}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	now := time.Now()
	if got := p.issuedRedirects(cfg, now); len(got) != 1 {
		t.Fatalf("matching snapshot and live: %d delegations", len(got))
	}
	if got := p.issuedRedirects(nil, now); got != nil {
		t.Fatal("nil snapshot delegates")
	}
	var nilProxy *Proxy
	if got := nilProxy.issuedRedirects(cfg, now); got != nil {
		t.Fatal("nil proxy delegates")
	}
	empty := config.Defaults()
	if got := p.issuedRedirects(empty, now); got != nil {
		t.Fatal("snapshot without a delegation delegates")
	}
	// A snapshot that holds a delegation the live policy lacks, or holds with
	// a different scope, delegates nothing; a different name or expiry still does.
	p.cfgPtr.Store(empty)
	if got := p.issuedRedirects(cfg, now); got != nil {
		t.Fatal("live policy without a delegation: snapshot still delegates")
	}
	p.cfgPtr.Store(nil)
	if got := p.issuedRedirects(cfg, now); got != nil {
		t.Fatal("no live policy: snapshot still delegates")
	}
	live := cfg.Clone()
	live.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins = []string{"https://moved.vendor.example"}
	p.cfgPtr.Store(live)
	if got := p.issuedRedirects(cfg, now); len(got) != 0 {
		t.Fatal("live policy with another scope: snapshot still delegates")
	}
	live = cfg.Clone()
	live.FetchProxy.Monitoring.IssuedRedirectDelegations[0].Name = "renamed"
	live.FetchProxy.Monitoring.IssuedRedirectDelegations[0].Expires = now.UTC().Add(96 * time.Hour).Format(time.DateOnly)
	p.cfgPtr.Store(live)
	if got := p.issuedRedirects(cfg, now); len(got) != 1 {
		t.Fatal("a rename or renewed expiry withdrew the delegation")
	}
	// Expiry is judged now, on both sides.
	p.cfgPtr.Store(cfg)
	if got := p.issuedRedirects(cfg, now.Add(10*24*time.Hour)); len(got) != 0 {
		t.Fatal("expired delegation still delegates")
	}
}

func TestCompileIssuedRedirectDelegationsFailsClosed(t *testing.T) {
	t.Parallel()
	now := time.Now()
	mk := func(mutate func(*config.IssuedRedirectDelegation)) *config.Config {
		d := delegationFixture()
		mutate(&d)
		cfg := config.Defaults()
		cfg.FetchProxy.Monitoring.IssuedRedirectDelegations = []config.IssuedRedirectDelegation{d}
		return cfg
	}
	if compileIssuedRedirectDelegations(nil, now) != nil || compileIssuedRedirectDelegations(config.Defaults(), now) != nil {
		t.Fatal("no configuration must compile to no delegations")
	}
	for name, cfg := range map[string]*config.Config{
		"malformed": mk(func(d *config.IssuedRedirectDelegation) { d.Name = "" }),
		// clock-literal-ok: deliberately expired negative case, independent of future clock changes.
		"expired": mk(func(d *config.IssuedRedirectDelegation) { d.Expires = "2000-01-01" }),
		"no valid route": mk(func(d *config.IssuedRedirectDelegation) {
			d.Source.PathPatterns = []string{"("}
			d.Source.PathPrefixes = nil
		}),
	} {
		if got := compileIssuedRedirectDelegations(cfg, now); len(got) != 0 {
			t.Errorf("%s: compiled %d delegations", name, len(got))
		}
	}
	// A listed origin that does not canonicalize leaves the delegation with no
	// target, so it delegates nothing rather than everything.
	cfg := mk(func(d *config.IssuedRedirectDelegation) {})
	cfg.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins = []string{"https://files.vendor.example"}
	if got := compileIssuedRedirectDelegations(cfg, now); len(got) != 1 || len(got[0].targets) != 1 {
		t.Fatalf("valid delegation compiled to %+v", got)
	}
}

func TestEntropyFinding(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		result scanner.Result
		want   bool
	}{
		"allowed":                {scanner.Result{Allowed: true}, false},
		"query entropy":          {scanner.Result{Scanner: scanner.ScannerEntropy, Class: scanner.ClassHeuristicEntropy}, true},
		"subdomain heuristic":    {scanner.Result{Scanner: scanner.ScannerSubdomainEntropy, Class: scanner.ClassHeuristicEntropy}, true},
		"subdomain structural":   {scanner.Result{Scanner: scanner.ScannerSubdomainEntropy}, false},
		"dlp":                    {scanner.Result{Scanner: scanner.ScannerDLP}, false},
		"ssrf":                   {scanner.Result{Scanner: scanner.ScannerSSRF}, false},
		"entropy-labelled other": {scanner.Result{Scanner: scanner.ScannerDLP, Class: scanner.ClassHeuristicEntropy}, false},
	} {
		if got := entropyFinding(tc.result); got != tc.want {
			t.Errorf("%s: entropyFinding = %t, want %t", name, got, tc.want)
		}
	}
}

func TestInterceptContextIssuedLocationGuards(t *testing.T) {
	t.Parallel()
	var nilCtx *InterceptContext
	nilCtx.recordIssuedLocation(delegationTestStore(t), "s", &http.Response{})
	nilCtx.recordIssuedLocation(nil, "s", nil)
	if nilCtx.issuedLocationAllowed(nil, "s", nil) {
		t.Fatal("nil context allowed")
	}
	ic := &InterceptContext{Config: config.Defaults(), Proxy: &Proxy{}}
	if ic.issuedLocationAllowed(delegationTestStore(t), "s", mustIssuerQueryURL(t, "https://files.vendor.example/a")) {
		t.Fatal("no delegation configured, yet allowed")
	}
	if ic.issuedLocationAllowed(nil, "s", nil) {
		t.Fatal("nil store allowed")
	}
	store := delegationTestStore(t)
	ic.recordIssuedLocation(store, "s", &http.Response{StatusCode: http.StatusFound}) // nothing configured
	if len(store.locations) != 0 {
		t.Fatal("minted without a delegation")
	}
	_ = envelope.ActorAuthBound
}

func TestWithIssuedLocationAllowanceNamesOnlyTheIssuedURL(t *testing.T) {
	t.Parallel()
	target := mustIssuerQueryURL(t, delegationFilesURL(delegationFilesPath, "a=1&a=2&b=3"))
	var used atomic.Bool
	ctx := withIssuedLocationAllowance(context.Background(), target, &used)
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	// Drive the three allowances through the scanner with values it would block.
	token := issuedTestToken()
	blocked := mustIssuerQueryURL(t, "https://"+delegationFilesHost+delegationFilesPath+"?k="+token)
	if res := sc.Scan(ctx, blocked.String()); res.Allowed {
		t.Fatal("a value the issued URL does not carry was relieved")
	}
	if used.Load() {
		t.Fatal("relief reported as used for a different URL")
	}
	carried := mustIssuerQueryURL(t, delegationFilesURL(delegationFilesPath, "k="+token))
	ctx = withIssuedLocationAllowance(context.Background(), carried, &used)
	if res := sc.Scan(ctx, carried.String()); !res.Allowed || !used.Load() {
		t.Fatalf("the issued URL was not relieved: %+v used=%t", res, used.Load())
	}
	// A different path on the same host does not get the path relief.
	used.Store(false)
	other := "https://" + delegationFilesHost + "/" + token + "/x"
	if res := sc.Scan(ctx, other); res.Allowed || used.Load() {
		t.Fatalf("another path was relieved: %+v", res)
	}
}

func TestFetchRedirectIssuedDelegationRejectsNonHTTPSLocation(t *testing.T) {
	good := "http://" + delegationFilesHost + delegationFilesPath + "?" + delegationTicketQuery()
	p, cfg, sc := delegationFetchProxy(t, nil)
	hop, via := fetchRedirectHop(t, cfg, sc, "", http.StatusFound, good, good)
	if _, used, ok := p.fetchIssuedRedirectContext(hop.Context(), cfg, hop); ok || used != nil {
		t.Fatal("an http Location produced relief")
	}
	_ = via
}
