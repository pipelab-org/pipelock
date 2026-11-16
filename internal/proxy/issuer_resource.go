// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/hmac"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/media"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/shield"
)

// issuerQueryResourcePath names the rule that admitted a request path only
// because an allowed, scanned and delivered HTML or CSS response from another
// origin declared that exact resource (a script, stylesheet, image or font the
// browser fetches). It is a statement about the path alone: the query, DLP,
// SSRF, blocklists, subdomain entropy, rate limits and data budgets all still
// apply to the request.
const issuerQueryResourcePath issuerQueryKind = "declared_resource_path"

// issuerDeliveryProof is what the handler that delivered a response can prove
// about its exchange. The zero value proves nothing, so a call site that does
// not fill it in can neither mint a cross-origin resource permission nor
// escape the provenance rules.
type issuerDeliveryProof struct {
	// cleanEnforced means the request passed every check in enforcing mode
	// with no audit or warn downgrade, and the response was scanned, allowed
	// and buffered to the client. Only then may the response name resources
	// on another origin.
	cleanEnforced bool
	// derived means the request's own URL was reachable only through
	// cross-origin resource evidence. Whatever such a response names stays
	// inside that grant: it may extend same-origin knowledge, but it never
	// becomes a root that names resources on a third origin.
	derived bool
}

// Resource evidence has no limits of its own. Its lifecycle is the existing issuer
// store's: entries share the digest list capacity, the session LRU, and the
// generation a reload replaces. There is deliberately no time-to-live; the
// store has none for any other evidence.

// appendDigestLocked records digest in the session's FIFO list unless already
// present. It reports whether the digest was newly added. The caller holds the
// ledger lock.
func (s *issuerQueryStore) appendDigestLocked(lists map[string][][32]byte, session string, digest [32]byte, now time.Time) bool {
	s.admitSessionLocked(session)
	held := lists[session]
	for _, existing := range held {
		if hmac.Equal(existing[:], digest[:]) {
			s.used[session] = now
			return false
		}
	}
	if len(held) >= issuerCookieMaxEntries {
		held = held[1:]
	}
	lists[session] = append(held, digest)
	s.used[session] = now
	return true
}

func digestListed(list [][32]byte, digest [32]byte) bool {
	for _, existing := range list {
		if hmac.Equal(existing[:], digest[:]) {
			return true
		}
	}
	return false
}

// rememberResource records that a root HTML or CSS response declared target's
// exact path as a resource. It reports whether a new entry was added.
func (s *issuerQueryStore) rememberResource(session string, target *url.URL, now time.Time) bool {
	if s == nil || session == "" {
		return false
	}
	digest, ok := s.pathDigest(target)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disabled || s.retired {
		return false
	}
	return s.appendDigestLocked(s.resources, session, digest, now)
}

// rememberDerivedPath records a same-origin path named by a response that was
// itself reached through cross-origin resource evidence.
func (s *issuerQueryStore) rememberDerivedPath(session string, target *url.URL, now time.Time) {
	if s == nil || session == "" {
		return
	}
	digest, ok := s.pathDigest(target)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disabled || s.retired {
		return
	}
	s.appendDigestLocked(s.derivedPaths, session, digest, now)
}

// resourcePathIssued reports whether target's exact path was declared as a
// resource, directly or by a response reached through such a declaration.
func (s *issuerQueryStore) resourcePathIssued(session string, target *url.URL) bool {
	if s == nil || session == "" {
		return false
	}
	digest, ok := s.pathDigest(target)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disabled || s.retired {
		return false
	}
	if digestListed(s.resources[session], digest) || digestListed(s.derivedPaths[session], digest) {
		s.used[session] = time.Now()
		return true
	}
	return false
}

// resourcePathIssuedContext waits only for a matching producer already being
// delivered to this session. Pending state grants nothing: every wake checks
// the live generation and delivered evidence again under the same lock.
func (s *issuerQueryStore) resourcePathIssuedContext(ctx context.Context, session string, target *url.URL) bool {
	if s == nil || session == "" {
		return false
	}
	digest, ok := s.pathDigest(target)
	if !ok {
		return false
	}
	for {
		s.mu.Lock()
		if s.disabled || s.retired {
			s.mu.Unlock()
			return false
		}
		if digestListed(s.resources[session], digest) || digestListed(s.derivedPaths[session], digest) {
			s.used[session] = time.Now()
			s.mu.Unlock()
			return true
		}
		// Cancellation stops waiting, but does not erase delivered evidence.
		// A read-side half-close can cancel an otherwise delivered exchange;
		// request scanning still independently checks its own context.
		if ctx.Err() != nil {
			s.mu.Unlock()
			return false
		}
		var done <-chan struct{}
		if bucket := s.resourceDeliveries[session]; bucket != nil {
			for delivery := range bucket.pending {
				if digestListed(delivery.resourcePaths, digest) {
					done = bucket.changed
					break
				}
			}
		}
		s.mu.Unlock()
		if done == nil {
			return false
		}
		select {
		case <-done:
		case <-ctx.Done():
			return false
		}
	}
}

// resourceDeliveryNotification retains one producer's completion callback for
// either the buffered or streaming response path. Repeated completion is safe.
type resourceDeliveryNotification struct{ finish func() }

func (d *resourceDeliveryNotification) begin(ic *InterceptContext, resp *http.Response, body []byte, proof issuerDeliveryProof) {
	if d.finish == nil {
		d.finish = ic.beginResourceDelivery(resp, body, proof)
	}
}

func (d *resourceDeliveryNotification) complete() {
	if d.finish != nil {
		d.finish()
	}
}

// beginResourceDelivery registers matching-path notification before a clean
// producer body is written. The existing delivered recorder remains the only
// place that mints authority. Failed writes, capacity pressure and retired
// generations therefore keep the ordinary path-entropy refusal.
func (ic *InterceptContext) beginResourceDelivery(resp *http.Response, body []byte, proof issuerDeliveryProof) func() {
	noop := func() {}
	if ic == nil || (!proof.cleanEnforced && !proof.derived) || resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return noop
	}
	store := ic.issuerQueryStore()
	if store == nil {
		return noop
	}
	origin := resp.Request.URL
	base := origin
	baseKnown := true
	originHost, originPort, _ := issuerCookieOrigin(origin)
	d := &issuedRedirectDelivery{done: make(chan struct{})}
	pathRemaining := issuerCookieMaxSetCookies
	observe := func(reference string, linkAttr bool) {
		if pathRemaining == 0 {
			return
		}
		ref, err := url.Parse(reference)
		if err != nil || (proof.derived && !issuerPathReference(reference, ref, linkAttr)) {
			return
		}
		if !ref.IsAbs() {
			if !baseKnown || base == nil {
				return
			}
			ref = base.ResolveReference(ref)
		}
		if proof.derived {
			// Match the delivered recorder: derived producers issue paths on
			// their own origin only, never query or onward authority.
			host, port, ok := issuerCookieOrigin(ref)
			if !ok || host != originHost || port != originPort {
				return
			}
		}
		pathRemaining--
		if digest, ok := store.pathDigest(ref); ok {
			d.resourcePaths = append(d.resourcePaths, digest)
		}
	}
	// Location spends the same path budget before body references in the
	// delivered recorder. Its validity does not depend on the body's charset.
	if proof.derived {
		if location, _ := issuerLocationReference(resp); location != "" {
			observe(location, false)
		}
	}
	var references []string
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	bodyEligible := asciiTransparentDocument(body, resp.Header.Get("Content-Type"))
	switch {
	case mediaType == "text/html" && bodyEligible:
		var baseHref string
		if proof.derived {
			references, _, baseHref, baseKnown = htmlLinkScan(body, issuerCookieMaxSetCookies, 0, nil)
		} else {
			_, references, baseHref, baseKnown = htmlLinkScan(body, 0, issuerCookieMaxSetCookies, origin)
		}
		var usable bool
		base, usable = sameOriginBase(origin, baseHref)
		baseKnown = baseKnown && usable
	case mediaType == "text/css" && bodyEligible:
		accept := sameOriginReferenceFilter(origin)
		if !proof.derived {
			accept = crossOriginResourceFilter(origin, base, true)
		}
		references = shield.CSSResourceURLs(string(body), pathRemaining, accept)
	case proof.derived && media.IsJavaScriptMediaType(mediaType) && bodyEligible:
		references = scriptURLReferences(body, pathRemaining)
	case proof.derived && (mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")):
		walkIssuerJSONStringValues(body, func(value string) bool {
			observe(value, false)
			return pathRemaining > 0
		})
	}
	for _, reference := range references {
		observe(reference, true)
	}
	session := sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
	if store.registerIssuerDelivery(session, d) != nil {
		return noop
	}
	return sync.OnceFunc(func() { store.finishIssuedRedirectDelivery(session, d) })
}

// resourceDerived reports whether target is known only through cross-origin
// resource evidence. A path its own origin linked from a root response is a
// root: the origin's own link outranks a declaration made by another origin.
// It never refreshes retention, so asking cannot keep evidence alive.
func (s *issuerQueryStore) resourceDerived(session string, target *url.URL) bool {
	if s == nil || session == "" {
		return false
	}
	digest, ok := s.pathDigest(target)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disabled || s.retired || digestListed(s.paths[session], digest) {
		return false
	}
	return digestListed(s.resources[session], digest) || digestListed(s.derivedPaths[session], digest)
}

// resourceDerived reports the provenance of the request being served, for the
// session the evidence is keyed to. An untrusted caller has no store.
func (ic *InterceptContext) resourceDerived(target *url.URL) bool {
	store := ic.issuerQueryStore()
	if store == nil || target == nil {
		return false
	}
	return store.resourceDerived(sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth), target)
}

// resourceBodyProbe replays the exact first read, including a one-shot error,
// before reading the original body again. Close still reaches the original.
type resourceBodyProbe struct {
	io.ReadCloser
	first   [1]byte
	n       int
	err     error
	pending bool
}

func (b *resourceBodyProbe) Read(p []byte) (int, error) {
	if !b.pending {
		return b.ReadCloser.Read(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	b.pending = false
	return copy(p, b.first[:b.n]), b.err
}

// resourceRequestShape reports whether r is a GET or HEAD that carries no body
// according to the request the HTTP server actually parsed, never according to
// a header the caller could have set to look bodyless. net/http gives HTTP/2
// requests a body reader even on an empty stream (Request.Body's server
// contract), so those readers must prove EOF. The probe preserves any bytes
// and error for ordinary body inspection if another URL allowance applies.
func resourceRequestShape(r *http.Request) bool {
	if r == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	if len(r.TransferEncoding) != 0 ||
		(r.ContentLength != 0 && (r.ProtoMajor != 2 || r.ContentLength != -1)) {
		return false
	}
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	if r.ProtoMajor != 2 {
		return false
	}
	probe := &resourceBodyProbe{ReadCloser: r.Body, pending: true}
	probe.n, probe.err = probe.ReadCloser.Read(probe.first[:])
	r.Body = probe
	return probe.n == 0 && errors.Is(probe.err, io.EOF)
}

// interceptCleanFacts are the intercept handler's own findings about one
// exchange, gathered at the point the response is delivered.
type interceptCleanFacts struct {
	urlResult             scanner.Result
	receiptVerdict        string
	hasFinding            bool
	policyObserved        bool
	responseScanExempt    bool
	authenticatedArtifact bool
}

// issuerExchangeEnforcedClean is the proof that gates cross-origin resource
// minting. Every audit or warn downgrade the handler tracks defeats it, so an
// exchange policy would have blocked cannot teach the proxy a destination.
func issuerExchangeEnforcedClean(ic *InterceptContext, facts interceptCleanFacts) bool {
	if ic == nil || ic.Config == nil || ic.Scanner == nil || !ic.Config.EnforceEnabled() {
		return false
	}
	if !ic.Scanner.ResponseScanningEnabled() || facts.responseScanExempt || facts.authenticatedArtifact {
		return false
	}
	if !facts.urlResult.Allowed || facts.urlResult.IsStructuralExemption() || len(facts.urlResult.WarnMatches) != 0 {
		return false
	}
	return !facts.hasFinding && !facts.policyObserved && facts.receiptVerdict == config.ActionAllow
}

type htmlAttr struct{ key, val string }

// sameOriginReferenceFilter applies the delivered observer's HTTPS origin
// boundary before bounded CSS collection. Keep query variants: each may carry
// a separate value that the ordinary same-origin observer records.
func sameOriginReferenceFilter(origin *url.URL) func(string) bool {
	host, port, valid := issuerCookieOrigin(origin)
	return func(value string) bool {
		if !valid {
			return false
		}
		ref, err := url.Parse(value)
		if err != nil {
			return false
		}
		ref = origin.ResolveReference(ref)
		refHost, refPort, ok := issuerCookieOrigin(ref)
		return ok && refHost == host && refPort == port
	}
}

// crossOriginResourceFilter counts only distinct paths that could actually
// become resource evidence. Its origin and path rules match pathDigest; query
// strings and fragments neither create another slot nor receive authority.
// Unknown or unusable document bases admit only absolute references.
func crossOriginResourceFilter(origin, base *url.URL, baseKnown bool) func(string) bool {
	host, port, validOrigin := issuerCookieOrigin(origin)
	type pathKey struct{ host, port, path string }
	seen := make(map[pathKey]bool)
	return func(value string) bool {
		if !validOrigin {
			return false
		}
		ref, err := url.Parse(value)
		if err != nil {
			return false
		}
		if !ref.IsAbs() {
			if !baseKnown || base == nil {
				return false
			}
			ref = base.ResolveReference(ref)
		}
		refHost, refPort, ok := issuerCookieOrigin(ref)
		path := issuerQueryPath(ref)
		if !ok || (refHost == host && refPort == port) || len(path) > issuerCookieMaxPairBytes {
			return false
		}
		key := pathKey{refHost, refPort, path}
		if seen[key] {
			return false
		}
		seen[key] = true
		return true
	}
}

// htmlResourceTags are the elements whose attributes can declare a resource.
func htmlResourceTag(tag string) bool {
	switch tag {
	case "script", "link", "img", "source":
		return true
	}
	return false
}

func firstAttr(attrs []htmlAttr, key string) (string, bool) {
	for _, a := range attrs {
		if a.key == key {
			return a.val, true
		}
	}
	return "", false
}

// scriptSourceFetched reports whether a script element's type makes a browser
// fetch its src: classic and module JavaScript only.
func scriptSourceFetched(scriptType string) bool {
	// WHATWG MIME Sniffing section 4.6 requires an essence-string match here,
	// unlike a response Content-Type. Parameters turn the element into data.
	typ := strings.ToLower(strings.TrimSpace(scriptType))
	return typ == "" || typ == "module" || media.IsJavaScriptMediaType(typ)
}

// htmlResourceRefs appends the URLs one start tag declares as subresources the
// browser fetches, up to limit. The declared element role is the proof; the
// file's name or shape is never consulted.
//   - script src (classic or module JavaScript);
//   - link href for stylesheet, modulepreload and icon, and for preload whose
//     as is script, style, image or font; a preload of an image with
//     imagesrcset names its srcset candidates instead;
//   - img src and srcset;
//   - source srcset inside picture. A source inside video or audio is media,
//     and its src has no effect inside picture, so neither names a resource.
//
// Anchors, forms, iframes, embeds, objects, prefetch, preconnect and anything a
// script computes are navigation or unproven and are not resources.
func htmlResourceRefs(tag string, attrs []htmlAttr, inPicture bool, out []string, limit int, accept func(string) bool) []string {
	add := func(v string) {
		if v = strings.TrimSpace(v); v != "" && len(out) < limit && (accept == nil || accept(v)) {
			out = append(out, v)
		}
	}
	addSrcset := func(v string) {
		for _, candidate := range srcsetURLs(v) {
			add(candidate)
		}
	}
	switch tag {
	case "script":
		typ, _ := firstAttr(attrs, "type")
		if src, ok := firstAttr(attrs, "src"); ok && scriptSourceFetched(typ) {
			add(src)
		}
	case "img":
		if src, ok := firstAttr(attrs, "src"); ok {
			add(src)
		}
		if set, ok := firstAttr(attrs, "srcset"); ok {
			addSrcset(set)
		}
	case "source":
		if set, ok := firstAttr(attrs, "srcset"); ok && inPicture {
			addSrcset(set)
		}
	case "link":
		rel, _ := firstAttr(attrs, "rel")
		href, hasHref := firstAttr(attrs, "href")
		for _, token := range strings.Fields(strings.ToLower(rel)) {
			switch token {
			case "stylesheet", "modulepreload", "icon":
				if hasHref {
					add(href)
				}
			case "preload":
				as, _ := firstAttr(attrs, "as")
				switch strings.ToLower(strings.TrimSpace(as)) {
				case "script", "style", "font":
					if hasHref {
						add(href)
					}
				case "image":
					if set, ok := firstAttr(attrs, "imagesrcset"); ok && strings.TrimSpace(set) != "" {
						addSrcset(set)
					} else if hasHref {
						add(href)
					}
				}
			}
		}
	}
	return out
}
