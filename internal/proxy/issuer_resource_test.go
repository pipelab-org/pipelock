// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/media"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	resourceSessionOne = "session-one"
	resourceCDN        = "https://cdn.vendor.example"
	resourceTok1       = "/p/Zk93mQ4vR7xT8bN2cL5wP1yH6dF3gJ0sQa7Ue9TnVb4X"
)

// TestHTMLLinkScanResourceRoles pins the typed producer list. Each row is one
// element and says whether its URL is a subresource the browser fetches.
func TestHTMLLinkScanResourceRoles(t *testing.T) {
	u := resourceCDN + "/a.bin"
	cases := []struct {
		name, html string
		want       []string
	}{
		{"script src", `<script src="` + u + `"></script>`, []string{u}},
		{"module script", `<script type="module" src="` + u + `"></script>`, []string{u}},
		{"js mime script", `<script type="text/javascript" src="` + u + `"></script>`, []string{u}},
		{"json script is data", `<script type="application/json" src="` + u + `"></script>`, nil},
		{"importmap script", `<script type="importmap" src="` + u + `"></script>`, nil},
		{"script without src", `<script>var u="` + u + `"</script>`, nil},
		{"stylesheet", `<link rel="stylesheet" href="` + u + `">`, []string{u}},
		{"stylesheet uppercase rel", `<link REL="StyleSheet" HREF="` + u + `">`, []string{u}},
		{"modulepreload", `<link rel="modulepreload" href="` + u + `">`, []string{u}},
		{"icon", `<link rel="icon" href="` + u + `">`, []string{u}},
		{"shortcut icon", `<link rel="shortcut icon" href="` + u + `">`, []string{u}},
		{"preload script", `<link rel="preload" as="script" href="` + u + `">`, []string{u}},
		{"preload style", `<link rel="preload" as="style" href="` + u + `">`, []string{u}},
		{"preload font", `<link rel="preload" as="font" href="` + u + `">`, []string{u}},
		{"preload image", `<link rel="preload" as="image" href="` + u + `">`, []string{u}},
		{"preload image srcset", `<link rel="preload" as="image" imagesrcset="` + u + ` 1x, ` + u + `2 2x" href="` + u + `3">`, []string{u, u + "2"}},
		{"preload fetch is computed", `<link rel="preload" as="fetch" href="` + u + `">`, nil},
		{"preload without as", `<link rel="preload" href="` + u + `">`, nil},
		{"preload video", `<link rel="preload" as="video" href="` + u + `">`, nil},
		{"prefetch", `<link rel="prefetch" href="` + u + `">`, nil},
		{"preconnect", `<link rel="preconnect" href="` + u + `">`, nil},
		{"dns-prefetch", `<link rel="dns-prefetch" href="` + u + `">`, nil},
		{"alternate", `<link rel="alternate" href="` + u + `">`, nil},
		{"canonical", `<link rel="canonical" href="` + u + `">`, nil},
		{"link without rel", `<link href="` + u + `">`, nil},
		{"img src", `<img src="` + u + `">`, []string{u}},
		{"img srcset", `<img srcset="` + u + ` 1x, ` + u + `2 2x">`, []string{u, u + "2"}},
		{"img lazy attr is not fetched", `<img data-src="` + u + `" data-srcset="` + u + `">`, nil},
		{"picture source", `<picture><source srcset="` + u + ` 1x"><img src="` + u + `0"></picture>`, []string{u, u + "0"}},
		{"source after picture closed", `<picture></picture><source srcset="` + u + `">`, nil},
		{"source in video is media", `<video><source src="` + u + `" srcset="` + u + `"></video>`, nil},
		{"source in audio is media", `<audio><source src="` + u + `"></audio>`, nil},
		{"picture source src has no effect", `<picture><source src="` + u + `"></picture>`, nil},
		{"anchor", `<a href="` + u + `">x</a>`, nil},
		{"form", `<form action="` + u + `"><input></form>`, nil},
		{"iframe", `<iframe src="` + u + `"></iframe>`, nil},
		{"frame embed object", `<embed src="` + u + `"><object data="` + u + `"></object>`, nil},
		{"video poster and src", `<video src="` + u + `" poster="` + u + `"></video>`, nil},
		{"inert text", `<p>` + u + `</p><!-- <img src="` + u + `"> -->`, nil},
		{"inside script text", `<script>document.write('<img src="` + u + `">')</script>`, nil},
		{"first duplicate attribute wins", `<img src="` + u + `" src="` + u + `2">`, []string{u}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got, _, _ := htmlLinkScan([]byte(tc.html), 100, 100, nil)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("resources = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHTMLResourceScriptMIMEEssence(t *testing.T) {
	for _, typ := range media.JavaScriptMediaTypes {
		t.Run(typ, func(t *testing.T) {
			_, resources, _, _ := htmlLinkScan([]byte(`<script type="`+strings.ToUpper(typ)+`" src="`+resourceCDN+`/entry.js"></script>`), 0, 1, nil)
			if len(resources) != 1 {
				t.Fatal("browser-supported classic script did not declare its resource")
			}
		})
	}
	for _, typ := range []string{"application/json", "importmap", "text/javascript;charset=utf-8", "module;charset=utf-8"} {
		if scriptSourceFetched(typ) {
			t.Fatalf("data-block type %q declared a resource", typ)
		}
	}
}

func TestHTMLLinkScanLimitsAndWrapper(t *testing.T) {
	var page strings.Builder
	for i := 0; i < 5; i++ {
		page.WriteString(`<img src="` + resourceCDN + `/i` + string(rune('0'+i)) + `.png"><a href="/l` + string(rune('0'+i)) + `">x</a>`)
	}
	body := []byte(page.String())
	links, resources, _, _ := htmlLinkScan(body, 3, 2, nil)
	if len(links) != 3 || len(resources) != 2 {
		t.Fatalf("links=%d resources=%d, want 3 and 2: independent limits", len(links), len(resources))
	}
	// The link limit being full must not stop resources, and the reverse.
	links, resources, _, _ = htmlLinkScan(body, 0, 4, nil)
	if len(links) != 0 || len(resources) != 4 {
		t.Fatalf("resource-only scan: links=%d resources=%d", len(links), len(resources))
	}
	links, resources, _, _ = htmlLinkScan(body, 4, 0, nil)
	if len(links) != 4 || len(resources) != 0 {
		t.Fatalf("link-only scan: links=%d resources=%d", len(links), len(resources))
	}
	if l, r, _, known := htmlLinkScan(body, 0, 0, nil); l != nil || r != nil || !known {
		t.Fatal("scan with no room must return nothing")
	}
	// The wrapper keeps the old contract: the same links, no resource work.
	wrapped, _, _ := htmlLinksAndBase(body, 100)
	scanned, _, _, _ := htmlLinkScan(body, 100, 100, nil)
	if !reflect.DeepEqual(wrapped, scanned) {
		t.Fatalf("wrapper links differ from scan links: %q vs %q", wrapped, scanned)
	}
}

func TestResourceRequestShape(t *testing.T) {
	get := func() *http.Request {
		r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://cdn.vendor.example/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	cases := []struct {
		name   string
		mutate func(*http.Request)
		want   bool
	}{
		{"get", func(*http.Request) {}, true},
		{"head", func(r *http.Request) { r.Method = http.MethodHead }, true},
		{"explicit zero length and NoBody", func(r *http.Request) { r.ContentLength = 0; r.Body = http.NoBody }, true},
		{"nil body", func(r *http.Request) { r.Body = nil }, true},
		{"post", func(r *http.Request) { r.Method = http.MethodPost }, false},
		{"put", func(r *http.Request) { r.Method = http.MethodPut }, false},
		{"options", func(r *http.Request) { r.Method = http.MethodOptions }, false},
		{"lowercase method is not GET", func(r *http.Request) { r.Method = "get" }, false},
		{"content length", func(r *http.Request) { r.ContentLength = 1 }, false},
		{"unknown length", func(r *http.Request) { r.ContentLength = -1 }, false},
		{"transfer encoding", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, false},
		{"identity transfer encoding", func(r *http.Request) { r.TransferEncoding = []string{"identity"} }, false},
		{"real body reader with zero length", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("x")) }, false},
		{"header says zero but body is real", func(r *http.Request) {
			r.Header.Set("Content-Length", "0")
			r.ContentLength = 3
			r.Body = io.NopCloser(strings.NewReader("abc"))
		}, false},
		{"h2 empty reader", func(r *http.Request) {
			r.ProtoMajor = 2
			r.Body = io.NopCloser(strings.NewReader(""))
		}, true},
		{"h2 empty unknown length", func(r *http.Request) {
			r.ProtoMajor, r.ContentLength = 2, -1
			r.Body = io.NopCloser(strings.NewReader(""))
		}, true},
		{"h2 nonempty zero length", func(r *http.Request) {
			r.ProtoMajor = 2
			r.Body = io.NopCloser(strings.NewReader("payload"))
		}, false},
		{"h2 read error", func(r *http.Request) {
			r.ProtoMajor = 2
			r.Body = io.NopCloser(failingIssuerQueryReader{})
		}, false},
		{"h2 byte and EOF", func(r *http.Request) {
			r.ProtoMajor = 2
			r.Body = &resourceProbeTestBody{data: "x", err: io.EOF}
		}, false},
		{"h1 opaque empty reader", func(r *http.Request) {
			r.ProtoMajor = 1
			r.Body = io.NopCloser(strings.NewReader(""))
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := get()
			tc.mutate(r)
			if got := resourceRequestShape(r); got != tc.want {
				t.Fatalf("shape = %v, want %v", got, tc.want)
			}
		})
	}
	if resourceRequestShape(nil) {
		t.Fatal("nil request accepted")
	}
}

// HTTP/2 server requests have a non-nil body reader even when the stream has
// no body. Test the server's real representation, not a hand-built request.
func TestResourceRequestShapeHTTP2(t *testing.T) {
	for _, tc := range []struct {
		name, method, body string
		unknownLength      bool
		want               int
	}{
		{"get", http.MethodGet, "", false, http.StatusOK},
		{"head", http.MethodHead, "", false, http.StatusOK},
		{"empty unknown length", http.MethodGet, "", true, http.StatusOK},
		{"body", http.MethodGet, "payload", false, http.StatusForbidden},
		{"unknown body", http.MethodGet, "payload", true, http.StatusForbidden},
		{"post", http.MethodPost, "", false, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				allowed := resourceRequestShape(r)
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != tc.body {
					t.Errorf("shape check changed the body: %q, %v", body, err)
				}
				if !allowed {
					w.WriteHeader(http.StatusForbidden)
				}
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			client := server.Client()
			client.Transport.(*http.Transport).ForceAttemptHTTP2 = true
			var body io.Reader
			if tc.body != "" || tc.unknownLength {
				body = io.NopCloser(strings.NewReader(tc.body))
			}
			req, err := http.NewRequestWithContext(t.Context(), tc.method, server.URL, body)
			if err != nil {
				t.Fatal(err)
			}
			if tc.unknownLength {
				req.ContentLength = -1
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.ProtoMajor != 2 || resp.StatusCode != tc.want {
				t.Fatalf("protocol=%s status=%d, want HTTP/2 status=%d", resp.Proto, resp.StatusCode, tc.want)
			}
		})
	}
}

type resourceProbeTestBody struct {
	data   string
	err    error
	read   bool
	closed bool
}

func (b *resourceProbeTestBody) Read(p []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}
	b.read = true
	return copy(p, b.data), b.err
}

func (b *resourceProbeTestBody) Close() error { b.closed = true; return nil }

func TestResourceRequestShapePreservesBodyErrors(t *testing.T) {
	for _, data := range []string{"", "x"} {
		t.Run(data, func(t *testing.T) {
			original := &resourceProbeTestBody{data: data, err: io.ErrUnexpectedEOF}
			req := &http.Request{Method: http.MethodGet, ProtoMajor: 2, Body: original}
			if resourceRequestShape(req) {
				t.Fatal("an incomplete body was reported empty")
			}
			if n, err := req.Body.Read(nil); n != 0 || err != nil {
				t.Fatalf("zero-length read consumed the pending result: %d, %v", n, err)
			}
			buf := make([]byte, 8)
			n, err := req.Body.Read(buf)
			if string(buf[:n]) != data || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("body scanner lost the original read result: %q, %v", buf[:n], err)
			}
			if err := req.Body.Close(); err != nil || !original.closed {
				t.Fatalf("body close was not forwarded: %v", err)
			}
		})
	}
}

func TestIssuerExchangeEnforcedClean(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	ic := &InterceptContext{Config: cfg, Scanner: sc}
	clean := interceptCleanFacts{urlResult: scanner.Result{Allowed: true}, receiptVerdict: config.ActionAllow}
	if !issuerExchangeEnforcedClean(ic, clean) {
		t.Fatal("positive control: a clean enforced exchange must qualify")
	}
	cases := []struct {
		name   string
		mutate func(*interceptCleanFacts)
	}{
		{"url not allowed", func(f *interceptCleanFacts) { f.urlResult.Allowed = false }},
		{"url warning", func(f *interceptCleanFacts) {
			f.urlResult.WarnMatches = []scanner.WarnMatch{{PatternName: "warned"}}
		}},
		{"structural exemption", func(f *interceptCleanFacts) { f.urlResult.Class = scanner.ClassStructuralExemption }},
		{"finding", func(f *interceptCleanFacts) { f.hasFinding = true }},
		{"policy observed", func(f *interceptCleanFacts) { f.policyObserved = true }},
		{"warn receipt", func(f *interceptCleanFacts) { f.receiptVerdict = config.ActionWarn }},
		{"empty receipt verdict", func(f *interceptCleanFacts) { f.receiptVerdict = "" }},
		{"response scan exempt", func(f *interceptCleanFacts) { f.responseScanExempt = true }},
		{"authenticated artifact", func(f *interceptCleanFacts) { f.authenticatedArtifact = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := clean
			tc.mutate(&facts)
			if issuerExchangeEnforcedClean(ic, facts) {
				t.Fatal("exchange with a downgrade counted as clean")
			}
		})
	}
	if issuerExchangeEnforcedClean(nil, clean) || issuerExchangeEnforcedClean(&InterceptContext{Scanner: sc}, clean) || issuerExchangeEnforcedClean(&InterceptContext{Config: cfg}, clean) {
		t.Fatal("missing config or scanner counted as clean")
	}
	audit := cfg.Clone()
	off := false
	audit.Enforce = &off
	if issuerExchangeEnforcedClean(&InterceptContext{Config: audit, Scanner: sc}, clean) {
		t.Fatal("audit mode counted as enforced")
	}
}

func newResourceStore(t *testing.T) (*issuerQueryStore, *InterceptContext) {
	t.Helper()
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	ic := &InterceptContext{Proxy: p, Config: cfg, Scanner: sc, Agent: "agent-one", ClientIP: "192.0.2.10", ActorAuth: envelope.ActorAuthBound}
	store := ic.issuerQueryStore()
	if store == nil {
		t.Fatal("trusted session has no store")
	}
	return store, ic
}

func TestIssuerResourceStore(t *testing.T) {
	store, _ := newResourceStore(t)
	now := time.Unix(100, 0)
	target := mustIssuerQueryURL(t, resourceCDN+resourceTok1+"/app.js")
	if store.resourcePathIssued(resourceSessionOne, target) {
		t.Fatal("path issued before it was declared")
	}
	if !store.rememberResource(resourceSessionOne, target, now) {
		t.Fatal("new resource not added")
	}
	if store.rememberResource(resourceSessionOne, target, now) {
		t.Fatal("repeat resource reported as new: it would spend the budget twice")
	}
	if !store.resourcePathIssued(resourceSessionOne, target) {
		t.Fatal("declared resource not issued")
	}
	for name, other := range map[string]*url.URL{
		"other host":     mustIssuerQueryURL(t, "https://other.vendor.example"+resourceTok1+"/app.js"),
		"other port":     mustIssuerQueryURL(t, resourceCDN+":8443"+resourceTok1+"/app.js"),
		"other path":     mustIssuerQueryURL(t, resourceCDN+resourceTok1+"/app.jsx"),
		"trailing slash": mustIssuerQueryURL(t, resourceCDN+resourceTok1+"/app.js/"),
		"cleartext":      mustIssuerQueryURL(t, "http://cdn.vendor.example"+resourceTok1+"/app.js"),
		"userinfo":       mustIssuerQueryURL(t, "https://u@cdn.vendor.example"+resourceTok1+"/app.js"),
	} {
		if store.resourcePathIssued(resourceSessionOne, other) {
			t.Errorf("%s: issued", name)
		}
	}
	// The query is not part of what was declared and is never kept.
	if !store.resourcePathIssued(resourceSessionOne, mustIssuerQueryURL(t, resourceCDN+resourceTok1+"/app.js?v=1")) {
		t.Fatal("the path is what a resource declares; its query is scored on its own")
	}
	if store.resourcePathIssued("other-session", target) || store.resourcePathIssued("", target) {
		t.Fatal("issued to another or empty session")
	}
	// A resource declaration and a same-origin link are different evidence.
	if store.pathIssued(resourceSessionOne, target) {
		t.Fatal("a resource declaration became a same-origin link")
	}
	// Derived same-origin paths are issued for resources only, never as links.
	derived := mustIssuerQueryURL(t, resourceCDN+"/derived/Qa7Ue9TnVb4XZk93mQ4vR7xT8bN2cL5wP1yH6dF3gJ0s.css")
	store.rememberDerivedPath(resourceSessionOne, derived, now)
	if !store.resourcePathIssued(resourceSessionOne, derived) || store.pathIssued(resourceSessionOne, derived) {
		t.Fatal("derived path must be a resource path and not a root link")
	}
	// Nil, empty, oversized and unusable targets issue nothing.
	var nilStore *issuerQueryStore
	if nilStore.rememberResource(resourceSessionOne, target, now) || nilStore.resourcePathIssued(resourceSessionOne, target) || nilStore.resourceDerived(resourceSessionOne, target) {
		t.Fatal("nil store issued")
	}
	nilStore.rememberDerivedPath(resourceSessionOne, target, now)
	if store.rememberResource("", target, now) {
		t.Fatal("empty session remembered")
	}
	store.rememberDerivedPath("", derived, now)
	huge := mustIssuerQueryURL(t, resourceCDN+"/"+strings.Repeat("z", issuerCookieMaxPairBytes+1))
	if store.rememberResource(resourceSessionOne, huge, now) || store.resourcePathIssued(resourceSessionOne, huge) {
		t.Fatal("oversized path kept")
	}
	store.rememberDerivedPath(resourceSessionOne, huge, now)
	if store.rememberResource(resourceSessionOne, mustIssuerQueryURL(t, "http://cdn.vendor.example/x"), now) {
		t.Fatal("cleartext resource kept")
	}
	if store.resourcePathIssued(resourceSessionOne, huge) || store.resourceDerived(resourceSessionOne, huge) {
		t.Fatal("unusable target issued")
	}
	disabled := newIssuerQueryStoreWithReader(failingIssuerQueryReader{})
	if disabled.rememberResource(resourceSessionOne, target, now) || disabled.resourcePathIssued(resourceSessionOne, target) || disabled.resourceDerived(resourceSessionOne, target) {
		t.Fatal("disabled store issued")
	}
	disabled.rememberDerivedPath(resourceSessionOne, target, now)
}

func TestIssuerResourceDerivedProvenance(t *testing.T) {
	store, ic := newResourceStore(t)
	now := time.Unix(100, 0)
	declared := mustIssuerQueryURL(t, resourceCDN+resourceTok1+"/a.css")
	if store.resourceDerived(resourceSessionOne, declared) {
		t.Fatal("unknown path reported derived")
	}
	store.rememberResource(resourceSessionOne, declared, now)
	if !store.resourceDerived(resourceSessionOne, declared) {
		t.Fatal("a path known only through a declaration must be derived")
	}
	// The origin's own link outranks another origin's declaration.
	store.rememberPath(resourceSessionOne, declared, now)
	if store.resourceDerived(resourceSessionOne, declared) {
		t.Fatal("a path its own origin linked is a root even when also declared")
	}
	child := mustIssuerQueryURL(t, resourceCDN+"/child/Qa7Ue9TnVb4XZk93mQ4vR7xT8bN2cL5wP1yH6dF3gJ0s.css")
	store.rememberDerivedPath(resourceSessionOne, child, now)
	if !store.resourceDerived(resourceSessionOne, child) {
		t.Fatal("a descendant of a declaration must stay derived")
	}
	if store.resourceDerived("other-session", child) {
		t.Fatal("provenance leaked to another session")
	}
	// Asking about provenance must not keep evidence alive.
	store.mu.Lock()
	store.used[resourceSessionOne] = time.Unix(1, 0)
	store.mu.Unlock()
	store.resourceDerived(resourceSessionOne, child)
	store.mu.Lock()
	used := store.used[resourceSessionOne]
	store.mu.Unlock()
	if !used.Equal(time.Unix(1, 0)) {
		t.Fatal("provenance lookup refreshed retention")
	}
	// The request-level helper keys on the same session as the producer.
	session := sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
	store.rememberResource(session, child, now)
	store.mu.Lock()
	delete(store.paths, session)
	store.mu.Unlock()
	if !ic.resourceDerived(child) {
		t.Fatal("trusted caller's derived request not recognized")
	}
	if ic.resourceDerived(nil) {
		t.Fatal("nil target derived")
	}
	untrusted := &InterceptContext{Proxy: ic.Proxy, Config: ic.Config, Agent: ic.Agent, ClientIP: ic.ClientIP, ActorAuth: envelope.ActorAuthSelfDeclared}
	if untrusted.resourceDerived(child) {
		t.Fatal("untrusted caller has no store and cannot be derived")
	}
}

func TestIssuerResourceCapacityEvictionAndGeneration(t *testing.T) {
	store, _ := newResourceStore(t)
	first := mustIssuerQueryURL(t, resourceCDN+"/first/Zk93mQ4vR7xT8bN2cL5wP1yH6dF3gJ0sQa7Ue9TnVb4X.js")
	store.rememberResource(resourceSessionOne, first, time.Unix(1, 0))
	derivedFirst := mustIssuerQueryURL(t, resourceCDN+"/dfirst/Zk93mQ4vR7xT8bN2cL5wP1yH6dF3gJ0sQa7Ue9TnVb4X.js")
	store.rememberDerivedPath(resourceSessionOne, derivedFirst, time.Unix(1, 0))
	for i := 0; i < issuerCookieMaxEntries; i++ {
		other := mustIssuerQueryURL(t, resourceCDN+"/r/"+strings.Repeat("a", 3)+time.Duration(i).String()+"/"+strings.Repeat("b", i%9)+"x.js")
		store.rememberResource(resourceSessionOne, other, time.Unix(int64(i+2), 0))
		store.rememberDerivedPath(resourceSessionOne, other, time.Unix(int64(i+2), 0))
	}
	store.mu.Lock()
	held, heldDerived := len(store.resources[resourceSessionOne]), len(store.derivedPaths[resourceSessionOne])
	store.mu.Unlock()
	if held != issuerCookieMaxEntries || heldDerived != issuerCookieMaxEntries {
		t.Fatalf("cap not enforced: %d resources, %d derived", held, heldDerived)
	}
	if store.resourcePathIssued(resourceSessionOne, first) || store.resourcePathIssued(resourceSessionOne, derivedFirst) {
		t.Fatal("evicted evidence still issued: it must return to ordinary scoring")
	}
	// Session LRU eviction drops both lists with the session.
	store.rememberResource("victim", first, time.Unix(1, 0))
	store.rememberDerivedPath("victim", first, time.Unix(1, 0))
	for i := 0; i < issuerCookieMaxSessions+1; i++ {
		store.rememberResource("s"+strings.Repeat("x", i), first, time.Unix(int64(i+10), 0))
	}
	store.mu.Lock()
	gone := len(store.resources["victim"]) + len(store.derivedPaths["victim"])
	store.mu.Unlock()
	if gone != 0 {
		t.Fatal("session eviction kept resource evidence")
	}
	// A new generation (a reload that turned a prerequisite off) starts empty,
	// and the replaced generation grants nothing and learns nothing.
	live := mustIssuerQueryURL(t, resourceCDN+"/live/Zk93mQ4vR7xT8bN2cL5wP1yH6dF3gJ0sQa7Ue9TnVb4X.js")
	store.rememberResource("fresh", live, time.Now())
	next := store.nextGeneration()
	if next.resourcePathIssued("fresh", live) {
		t.Fatal("new generation kept resource evidence")
	}
	if store.resourcePathIssued("fresh", live) || store.resourceDerived("fresh", live) {
		t.Fatal("retired generation still grants")
	}
	if store.rememberResource("fresh", first, time.Now()) {
		t.Fatal("retired generation learned a resource")
	}
	store.rememberDerivedPath("fresh", first, time.Now())
	store.mu.Lock()
	leaked := len(store.derivedPaths["fresh"])
	store.mu.Unlock()
	if leaked != 0 {
		t.Fatal("retired generation learned a derived path")
	}
	if !next.rememberResource("fresh", live, time.Now()) || !next.resourcePathIssued("fresh", live) {
		t.Fatal("new generation cannot learn")
	}
}

// recordProducer records one delivered 200 response, so a producer test never
// holds a response of its own.
func recordProducer(t *testing.T, ic *InterceptContext, rawURL, contentType, body string, proof issuerDeliveryProof) {
	t.Helper()
	resp := &http.Response{
		Request:    &http.Request{URL: mustIssuerQueryURL(t, rawURL)},
		Header:     http.Header{"Content-Type": {contentType}},
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
	}
	defer func() { _ = resp.Body.Close() }()
	recordDeliveredIssuerQueryProof(ic, resp, []byte(body), true, proof)
}

func TestRecordDeliveredResourceProducers(t *testing.T) {
	root := issuerDeliveryProof{cleanEnforced: true}
	target := func(path string) *url.URL { return mustIssuerQueryURL(t, resourceCDN+path) }
	issued := func(store *issuerQueryStore, path string) bool {
		return store.resourcePathIssued(sessionKeyFor(nil, "agent-one", "192.0.2.10", envelope.ActorAuthBound), target(path))
	}
	cases := []struct {
		name, contentType, body string
		pageURL                 string
		proof                   issuerDeliveryProof
		issued                  map[string]bool
	}{
		{
			name: "html typed elements", contentType: "text/html", pageURL: "https://www.vendor.example/", proof: root,
			body:   `<script src="` + resourceCDN + `/s.js"></script><img src="//cdn.vendor.example/i.png"><a href="` + resourceCDN + `/a">x</a>`,
			issued: map[string]bool{"/s.js": true, "/i.png": true, "/a": false},
		},
		{
			name: "zero proof mints nothing", contentType: "text/html", pageURL: "https://www.vendor.example/",
			body: `<script src="` + resourceCDN + `/s.js"></script>`, issued: map[string]bool{"/s.js": false},
		},
		{
			name: "derived proof mints nothing", contentType: "text/html", pageURL: "https://www.vendor.example/",
			proof: issuerDeliveryProof{cleanEnforced: true, derived: true},
			body:  `<script src="` + resourceCDN + `/s.js"></script>`, issued: map[string]bool{"/s.js": false},
		},
		{
			name: "unclean proof mints nothing", contentType: "text/html", pageURL: "https://www.vendor.example/",
			proof: issuerDeliveryProof{derived: false},
			body:  `<script src="` + resourceCDN + `/s.js"></script>`, issued: map[string]bool{"/s.js": false},
		},
		{
			name: "css url and import", contentType: "text/css", pageURL: "https://www.vendor.example/site.css", proof: root,
			body:   `@import url("` + resourceCDN + `/imp.css"); a{background:url(` + resourceCDN + `/bg.png)} @font-face{src:url('` + resourceCDN + `/f.woff2')}`,
			issued: map[string]bool{"/imp.css": true, "/bg.png": true, "/f.woff2": true},
		},
		{
			name: "css without proof", contentType: "text/css", pageURL: "https://www.vendor.example/site.css",
			body: `a{background:url(` + resourceCDN + `/bg.png)}`, issued: map[string]bool{"/bg.png": false},
		},
		{
			name: "css derived", contentType: "text/css", pageURL: "https://www.vendor.example/site.css",
			proof: issuerDeliveryProof{cleanEnforced: true, derived: true},
			body:  `a{background:url(` + resourceCDN + `/bg.png)}`, issued: map[string]bool{"/bg.png": false},
		},
		{
			name: "script literal is same-origin knowledge only", contentType: "text/javascript", pageURL: "https://www.vendor.example/app.js", proof: root,
			body: `var u = "` + resourceCDN + `/lit.js"; import("` + resourceCDN + `/dyn.js")`, issued: map[string]bool{"/lit.js": false, "/dyn.js": false},
		},
		{
			name: "html inert text and comments", contentType: "text/html", pageURL: "https://www.vendor.example/", proof: root,
			body:   `<p>` + resourceCDN + `/t.js</p><!-- <script src="` + resourceCDN + `/c.js"></script> --><script>var s="<img src='` + resourceCDN + `/q.png'>"</script>`,
			issued: map[string]bool{"/t.js": false, "/c.js": false, "/q.png": false},
		},
		{
			name: "xhtml issues nothing", contentType: "application/xhtml+xml", pageURL: "https://www.vendor.example/", proof: root,
			body: `<script src="` + resourceCDN + `/x.js"></script>`, issued: map[string]bool{"/x.js": false},
		},
		{
			name: "json issues nothing", contentType: "application/json", pageURL: "https://www.vendor.example/", proof: root,
			body: `{"src":"` + resourceCDN + `/j.js"}`, issued: map[string]bool{"/j.js": false},
		},
		{
			name: "cross-origin base hides relative references", contentType: "text/html", pageURL: "https://www.vendor.example/", proof: root,
			body:   `<base href="` + resourceCDN + `/"><script src="rel.js"></script><script src="` + resourceCDN + `/abs.js"></script>`,
			issued: map[string]bool{"/rel.js": false, "/abs.js": true},
		},
		{
			name: "same-origin references are not resources", contentType: "text/html", pageURL: "https://cdn.vendor.example/", proof: root,
			body: `<script src="/own.js"></script><script src="` + resourceCDN + `/own2.js"></script>`, issued: map[string]bool{"/own.js": false, "/own2.js": false},
		},
		{
			name: "cleartext target is not an https origin", contentType: "text/html", pageURL: "https://www.vendor.example/", proof: root,
			body: `<script src="http://cdn.vendor.example/clear.js"></script>`, issued: map[string]bool{"/clear.js": false},
		},
		{
			name: "non ascii transparent encoding", contentType: "text/html; charset=utf-16", pageURL: "https://www.vendor.example/", proof: root,
			body: `<script src="` + resourceCDN + `/u.js"></script>`, issued: map[string]bool{"/u.js": false},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, ic := newResourceStore(t)
			recordProducer(t, ic, tc.pageURL, tc.contentType, tc.body, tc.proof)
			for path, want := range tc.issued {
				if got := issued(store, path); got != want {
					t.Errorf("%s issued = %v, want %v", path, got, want)
				}
			}
		})
	}
}

func TestRecordDeliveredResourceQueryIsNeverKept(t *testing.T) {
	store, ic := newResourceStore(t)
	token := issuedTestToken()
	body := `<script src="` + resourceCDN + `/q.js?v=` + token + `"></script>`
	recordProducer(t, ic, "https://www.vendor.example/", "text/html", body, issuerDeliveryProof{cleanEnforced: true})
	session := sessionKeyFor(nil, "agent-one", "192.0.2.10", envelope.ActorAuthBound)
	withQuery := mustIssuerQueryURL(t, resourceCDN+"/q.js?v="+token)
	if !store.resourcePathIssued(session, withQuery) {
		t.Fatal("positive control: the declared path must be issued")
	}
	if store.allows(session, withQuery, "v", token) {
		t.Fatal("the query a resource reference carried was recorded as issued evidence")
	}
	if _, ok := store.match(session, withQuery, "v", token); ok {
		t.Fatal("the query a resource reference carried matches evidence")
	}
}

func TestRecordDeliveredDerivedResourceOnlyIssuesPaths(t *testing.T) {
	store, ic := newResourceStore(t)
	session := sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
	token := issuedTestToken()
	target := mustIssuerQueryURL(t, resourceCDN+"/dep.js?v="+token)
	recordProducer(t, ic, resourceCDN+"/entry", "text/html", `<script src="`+target.String()+`"></script>`, issuerDeliveryProof{cleanEnforced: true, derived: true})
	if !store.resourcePathIssued(session, target) {
		t.Fatal("positive control: the same-origin derived path was not retained")
	}
	if store.allows(session, target, "v", token) {
		t.Error("a derived response issued query authority")
	}
	if store.documentServed(session, mustIssuerQueryURL(t, resourceCDN)) {
		t.Error("a derived response issued page-origin authority")
	}
}

func TestRecordDeliveredDerivedResourceCannotDeclareOAuth(t *testing.T) {
	store, ic := newResourceStore(t)
	session := sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
	callback := mustIssuerQueryURL(t, "https://app.vendor.example/callback")
	authorize := resourceCDN + "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {callback.String()},
	}.Encode()
	server := mustIssuerQueryURL(t, authorize)
	recordProducer(t, ic, authorize, "application/json", `{}`, issuerDeliveryProof{derived: true})
	if store.redirectDeclared(session, server, callback) {
		t.Fatal("a derived response declared a callback for a future root response")
	}
	recordProducer(t, ic, authorize, "application/json", `{}`, issuerDeliveryProof{})
	if !store.redirectDeclared(session, server, callback) {
		t.Fatal("positive control: an independent root still declares its callback")
	}
}

func TestRecordDeliveredResourceBudgetsAndDerivedPaths(t *testing.T) {
	store, ic := newResourceStore(t)
	session := sessionKeyFor(nil, "agent-one", "192.0.2.10", envelope.ActorAuthBound)
	var page strings.Builder
	total := issuerCookieMaxSetCookies + 20
	for i := 0; i < total; i++ {
		page.WriteString(`<img src="` + resourceCDN + `/img/` + time.Duration(i).String() + `.png">`)
	}
	recordProducer(t, ic, "https://www.vendor.example/", "text/html", page.String(), issuerDeliveryProof{cleanEnforced: true})
	store.mu.Lock()
	held := len(store.resources[session])
	store.mu.Unlock()
	if held != issuerCookieMaxSetCookies {
		t.Fatalf("one response declared %d resources, want the existing per-response budget %d", held, issuerCookieMaxSetCookies)
	}
	// Same-origin links cannot starve resources and the reverse.
	store2, ic2 := newResourceStore(t)
	var mixed strings.Builder
	for i := 0; i < issuerCookieMaxSetCookies+5; i++ {
		mixed.WriteString(`<a href="/l/` + time.Duration(i).String() + `">x</a>`)
	}
	mixed.WriteString(`<script src="` + resourceCDN + `/late.js"></script>`)
	recordProducer(t, ic2, "https://www.vendor.example/", "text/html", mixed.String(), issuerDeliveryProof{cleanEnforced: true})
	if !store2.resourcePathIssued(session, mustIssuerQueryURL(t, resourceCDN+"/late.js")) {
		t.Fatal("same-origin links starved the cross-origin resource budget")
	}
	// A derived response records same-origin links as derived, never as roots.
	store3, ic3 := newResourceStore(t)
	recordProducer(t, ic3, resourceCDN+"/d.css", "text/css", `a{background:url(/dep.png)}`, issuerDeliveryProof{derived: true})
	dep := mustIssuerQueryURL(t, resourceCDN+"/dep.png")
	if store3.pathIssued(session, dep) || !store3.resourcePathIssued(session, dep) {
		t.Fatal("derived response must record a derived path, not a root path")
	}
	// A root response records an ordinary path.
	store4, ic4 := newResourceStore(t)
	recordProducer(t, ic4, resourceCDN+"/d.css", "text/css", `a{background:url(/dep.png)}`, issuerDeliveryProof{})
	if !store4.pathIssued(session, dep) || store4.resourcePathIssued(session, dep) {
		t.Fatal("root response must keep recording an ordinary path")
	}
	// A derived redirect Location stays derived too.
	store5, ic5 := newResourceStore(t)
	redirect := &http.Response{
		Request: &http.Request{URL: mustIssuerQueryURL(t, resourceCDN+"/d.css")}, StatusCode: http.StatusFound,
		Header: http.Header{"Location": {"/next/Zk93mQ4vR7xT8bN2cL5wP1yH6dF3gJ0sQa7Ue9TnVb4X"}},
	}
	recordDeliveredIssuerQueryProof(ic5, redirect, nil, true, issuerDeliveryProof{derived: true})
	next := mustIssuerQueryURL(t, resourceCDN+"/next/Zk93mQ4vR7xT8bN2cL5wP1yH6dF3gJ0sQa7Ue9TnVb4X")
	if store5.pathIssued(session, next) || !store5.resourcePathIssued(session, next) {
		t.Fatal("derived redirect must record a derived path")
	}
	// A redirect to another origin never declares a resource.
	store6, ic6 := newResourceStore(t)
	cross := &http.Response{
		Request: &http.Request{URL: mustIssuerQueryURL(t, "https://www.vendor.example/go")}, StatusCode: http.StatusFound,
		Header: http.Header{"Location": {resourceCDN + "/landing.js"}},
	}
	recordDeliveredIssuerQueryProof(ic6, cross, nil, true, issuerDeliveryProof{cleanEnforced: true})
	if store6.resourcePathIssued(session, mustIssuerQueryURL(t, resourceCDN+"/landing.js")) {
		t.Fatal("a redirect declared a resource")
	}
}

// TestResourceDLPStillRunsOnADeclaredPath states what the permission is not:
// with the path allowance returning true, the DLP floor still blocks.
func TestResourceDLPStillRunsOnADeclaredPath(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	secret := "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
	allowAll := scanner.WithIssuerPathAllowance(context.Background(), func(string) bool { return true })
	if result := sc.Scan(allowAll, resourceCDN+"/assets/"+secret+"/app.js"); result.Allowed {
		t.Fatalf("a declared path carrying a credential was allowed: %+v", result)
	}
	tok := issuedTestToken()
	if result := sc.Scan(scanner.WithIssuerPathAllowance(context.Background(), func(string) bool { return true }), resourceCDN+resourceTok1+"/app.js?v="+tok); result.Allowed || result.Scanner != scanner.ScannerEntropy {
		t.Fatalf("a high-entropy query behind a relieved path was not scored: %+v", result)
	}
	if result := sc.Scan(allowAll, resourceCDN+resourceTok1+"/app.js"); !result.Allowed {
		t.Fatalf("positive control: the relieved path alone must pass: %+v", result)
	}
}

// A stylesheet that references more same-origin URLs than the lexer limit must
// still declare the CDN resource that follows them.
func TestRecordDeliveredResourceCSSRoom(t *testing.T) {
	store, ic := newResourceStore(t)
	var css strings.Builder
	for i := 0; i < issuerCookieMaxSetCookies+10; i++ {
		css.WriteString(`.c` + time.Duration(i).String() + `{background:url(/own/` + time.Duration(i).String() + `.png)}`)
	}
	css.WriteString(`@font-face{src:url(` + resourceCDN + `/late.woff2)}`)
	recordProducer(t, ic, "https://www.vendor.example/s.css", "text/css", css.String(), issuerDeliveryProof{cleanEnforced: true})
	session := sessionKeyFor(nil, "agent-one", "192.0.2.10", envelope.ActorAuthBound)
	if !store.resourcePathIssued(session, mustIssuerQueryURL(t, resourceCDN+"/late.woff2")) {
		t.Fatal("same-origin references used up the limit before the CDN reference")
	}
}

func TestRecordDeliveredResourceBudgetCountsEligiblePaths(t *testing.T) {
	for _, mediaType := range []string{"text/html", "text/css"} {
		for _, noise := range []struct {
			name, reference string
		}{
			{"same origin", "/own/image.png"},
			{"data placeholder", "data:image/png;base64,AAAA"},
			{"blob placeholder", "blob:https://www.vendor.example/image"},
			{"cleartext", "http://cdn.vendor.example/image.png"},
			{"malformed URL", "https://%zz/image.png"},
			{"duplicate path", resourceCDN + "/repeated.png"},
		} {
			t.Run(mediaType+"/"+noise.name, func(t *testing.T) {
				store, ic := newResourceStore(t)
				var body strings.Builder
				add := func(reference string) {
					if mediaType == "text/html" {
						body.WriteString(`<img src="` + reference + `">`)
					} else {
						body.WriteString(`a{background:url("` + reference + `")}`)
					}
				}
				for i := 0; i < 2*issuerCookieMaxSetCookies+10; i++ {
					add(noise.reference)
				}
				late := resourceCDN + resourceTok1
				add(late)
				recordProducer(t, ic, "https://www.vendor.example/root", mediaType, body.String(), issuerDeliveryProof{cleanEnforced: true})
				session := sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
				if !store.resourcePathIssued(session, mustIssuerQueryURL(t, late)) {
					t.Fatal("ineligible or repeated references exhausted the resource budget")
				}
				store.mu.Lock()
				held := len(store.resources[session])
				store.mu.Unlock()
				want := 1
				if noise.name == "duplicate path" {
					want++
				}
				if held != want {
					t.Fatalf("recorded %d resource paths, want %d", held, want)
				}
			})
		}
	}
}

func TestCrossOriginResourceFilter(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://www.vendor.example/page")
	for _, tc := range []struct {
		name, reference string
		baseKnown       bool
		want            bool
	}{
		{"absolute", resourceCDN + "/image.png", true, true},
		{"absolute with unknown base", resourceCDN + "/image.png", false, true},
		{"scheme relative", "//cdn.vendor.example/image.png", true, true},
		{"scheme relative with unknown base", "//cdn.vendor.example/image.png", false, false},
		{"same origin", "/own.png", true, false},
		{"same origin canonical port", "https://WWW.vendor.example:443/own.png", true, false},
		{"credentials", "https://user@cdn.vendor.example/image.png", true, false},
		{"oversize path", resourceCDN + "/" + strings.Repeat("x", issuerCookieMaxPairBytes), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accept := crossOriginResourceFilter(origin, origin, tc.baseKnown)
			if got := accept(tc.reference); got != tc.want {
				t.Fatalf("accepted = %v, want %v", got, tc.want)
			}
		})
	}
	if crossOriginResourceFilter(nil, origin, true)(resourceCDN + "/image.png") {
		t.Fatal("invalid producer origin accepted")
	}
	if crossOriginResourceFilter(origin, nil, true)("//cdn.vendor.example/image.png") {
		t.Fatal("relative reference without a base accepted")
	}
	accept := crossOriginResourceFilter(origin, origin, true)
	if !accept(resourceCDN + "/image.png?x=one#first") {
		t.Fatal("positive control: first path rejected")
	}
	if accept("https://CDN.vendor.example:443/image.png?x=two#second") {
		t.Fatal("query, fragment or equivalent origin spelling spent another slot")
	}
}

func TestResourcePendingDeliveryInactiveState(t *testing.T) {
	store, _ := newResourceStore(t)
	target := mustIssuerQueryURL(t, resourceCDN+resourceTok1)
	var missing *issuerQueryStore
	ctx := t.Context()
	if missing.resourcePathIssuedContext(ctx, resourceSessionOne, target) ||
		store.resourcePathIssuedContext(ctx, "", target) ||
		store.resourcePathIssuedContext(ctx, resourceSessionOne, mustIssuerQueryURL(t, resourceCDN+"/"+strings.Repeat("x", issuerCookieMaxPairBytes))) {
		t.Fatal("missing identity or unusable path acquired pending evidence")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if store.resourcePathIssuedContext(cancelled, resourceSessionOne, target) {
		t.Fatal("cancelled lookup acquired pending evidence")
	}
	d := &issuedRedirectDelivery{resourcePaths: [][32]byte{{1}}, done: make(chan struct{})}
	if missing.registerIssuerDelivery(resourceSessionOne, d) == nil || store.registerIssuerDelivery("", d) == nil {
		t.Fatal("missing identity registered a delivery")
	}
	store.nextGeneration()
	if store.registerIssuerDelivery(resourceSessionOne, d) == nil {
		t.Fatal("retired generation registered a delivery")
	}
}
