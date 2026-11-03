// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/hmac"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/reqpolicy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// issuerQueryIssuedRedirect is the receipt label for relief that came from an
// operator-declared redirect delegation (fetch_proxy.monitoring.
// issued_redirect_delegations). The extension is advisory metadata, not part of
// the signed action record.
const issuerQueryIssuedRedirect issuerQueryKind = "issued_redirect"

// issuedRedirectSourcePort is the only source port a delegation honors: the
// HTTPS default. The route grammar names hosts, not authorities, so honoring any
// port would let a different service on the same host name issue redirects.
const issuedRedirectSourcePort = "443"

// canonicalRedirectHost folds an authority host to the form destination
// matching uses for configured hosts: case-folded, one trailing root dot
// removed, IDNA lookup form so a Unicode name and its punycode spelling are one
// host. IP literals stay exact. A failed lookup keeps the input rather than
// widening it.
func canonicalRedirectHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || net.ParseIP(host) != nil {
		return host
	}
	ascii, err := destination.LookupASCII(host)
	if err != nil || ascii == "" {
		return host
	}
	return strings.ToLower(strings.TrimSuffix(ascii, "."))
}

// issuedRedirectAuthority returns the canonical https authority of u. Only
// https without userinfo qualifies: the delegation's targets are https origins
// (RFC 6454 section 4: scheme, host and port identify an origin).
func issuedRedirectAuthority(u *url.URL) (host, port string, ok bool) {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return "", "", false
	}
	host = canonicalRedirectHost(u.Hostname())
	port = effectiveURLPort(u)
	return host, port, host != "" && port != ""
}

// issuedLocationCanonical is the exact-request identity of an issued URL:
// scheme, canonical host, effective port, escaped path and the whole query
// multiset. Query order may change; no name or value may be added, removed,
// duplicated or altered. A query that does not parse (a ";" separator, a
// malformed escape) has no identity, so it is never minted or matched.
func issuedLocationCanonical(u *url.URL) (string, bool) {
	host, port, ok := issuedRedirectAuthority(u)
	if !ok {
		return "", false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", false
	}
	for _, values := range query {
		slices.Sort(values)
	}
	return strings.Join([]string{u.Scheme, host, port, u.EscapedPath(), query.Encode()}, "\x00"), true
}

// issuedRedirectDelegation is one active, compiled declaration.
type issuedRedirectDelegation struct {
	source  *reqpolicy.RouteMatcher
	targets map[string]struct{} // canonical "host\x00port"
	scope   [32]byte
}

// compileIssuedRedirectDelegations returns the active declarations of cfg. A
// configuration that does not validate delegates nothing.
func compileIssuedRedirectDelegations(cfg *config.Config, now time.Time) []issuedRedirectDelegation {
	if cfg == nil || len(cfg.FetchProxy.Monitoring.IssuedRedirectDelegations) == 0 {
		return nil
	}
	entries, err := config.NormalizeIssuedRedirectDelegations(cfg.FetchProxy.Monitoring.IssuedRedirectDelegations)
	if err != nil {
		return nil
	}
	out := make([]issuedRedirectDelegation, 0, len(entries))
	for _, entry := range entries {
		if !config.IssuedRedirectDelegationActive(entry, now) {
			continue
		}
		source, err := reqpolicy.NewRouteMatcher(entry.Source)
		if err != nil {
			continue
		}
		targets := make(map[string]struct{}, len(entry.TargetOrigins))
		for _, origin := range entry.TargetOrigins {
			parsed, err := url.Parse(origin)
			if err != nil {
				continue
			}
			if host, port, ok := issuedRedirectAuthority(parsed); ok {
				targets[host+"\x00"+port] = struct{}{}
			}
		}
		if len(targets) == 0 {
			continue
		}
		out = append(out, issuedRedirectDelegation{source: source, targets: targets, scope: config.IssuedRedirectDelegationScope(entry)})
	}
	return out
}

// issuedRedirects returns the delegations in force for a request: those in the
// request's configuration snapshot that are also active, with the same scope,
// in the live configuration. Either side dropping, narrowing or expiring a
// delegation withdraws it for old snapshots and open sessions alike.
func (p *Proxy) issuedRedirects(cfg *config.Config, now time.Time) []issuedRedirectDelegation {
	if p == nil || cfg == nil || len(cfg.FetchProxy.Monitoring.IssuedRedirectDelegations) == 0 {
		return nil
	}
	live := p.cfgPtr.Load()
	if live == nil || len(live.FetchProxy.Monitoring.IssuedRedirectDelegations) == 0 {
		return nil
	}
	mine := compileIssuedRedirectDelegations(cfg, now)
	if live == cfg || len(mine) == 0 {
		return mine
	}
	current := make(map[[32]byte]struct{})
	for _, d := range compileIssuedRedirectDelegations(live, now) {
		current[d.scope] = struct{}{}
	}
	out := mine[:0]
	for _, d := range mine {
		if _, ok := current[d.scope]; ok {
			out = append(out, d)
		}
	}
	return out
}

func issuedRedirectScopes(delegations []issuedRedirectDelegation) map[[32]byte]struct{} {
	scopes := make(map[[32]byte]struct{}, len(delegations))
	for _, d := range delegations {
		scopes[d.scope] = struct{}{}
	}
	return scopes
}

// admits reports whether this delegation covers a redirect that source's
// response issued to target: the source request's host, method and path match
// the declared route on the https default port, and target is on a listed
// origin.
func (d issuedRedirectDelegation) admits(source *http.Request, target *url.URL) bool {
	if source == nil || source.URL == nil {
		return false
	}
	host, port, ok := issuedRedirectAuthority(source.URL)
	if !ok || port != issuedRedirectSourcePort {
		return false
	}
	if !d.source.Matches(host, source.Method, source.URL.EscapedPath()) {
		return false
	}
	targetHost, targetPort, ok := issuedRedirectAuthority(target)
	if !ok {
		return false
	}
	_, listed := d.targets[targetHost+"\x00"+targetPort]
	return listed
}

// issuedRedirectLocation extracts the one unambiguous redirect target a
// response issued, resolved against the request that produced it (RFC 3986
// section 5; RFC 9110 sections 10.2.2 and 15.4). Only the redirect statuses a
// client follows automatically qualify, with exactly one Location value and no
// character a browser might read differently. maxLen is the scanner's URL
// length limit: a longer Location can never be admitted, so it is not minted.
func issuedRedirectLocation(resp *http.Response, maxLen int) (*url.URL, bool) {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return nil, false
	}
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return nil, false
	}
	locations := resp.Header.Values("Location")
	if len(locations) != 1 || locations[0] == "" || ambiguousLocationValues(locations) {
		return nil, false
	}
	if maxLen > 0 && len(locations[0]) > maxLen {
		return nil, false
	}
	ref, err := url.Parse(locations[0])
	if err != nil {
		return nil, false
	}
	target := resp.Request.URL.ResolveReference(ref)
	// A fragment is never sent in a request target (RFC 9110 section 7.1).
	target.Fragment = ""
	return target, true
}

// issuedLocationEntry holds keyed digests only: the exact issued URL, its
// authority (for the CONNECT that precedes it), and the scope of the
// delegation that admitted it.
type issuedLocationEntry struct {
	url       [32]byte
	authority [32]byte
	scope     [32]byte
}

func (s *issuerQueryStore) issuedLocationDigest(canonical string) [32]byte {
	return s.digestFields("issued_redirect_url", canonical)
}

func (s *issuerQueryStore) issuedAuthorityDigest(host, port string) [32]byte {
	return s.digestFields("issued_redirect_authority", "https", host, port)
}

// rememberIssuedLocation records that the session was delivered a redirect to
// target under the delegation with this scope.
func (s *issuerQueryStore) rememberIssuedLocation(session string, target *url.URL, scope [32]byte, now time.Time) {
	if s == nil || s.disabled || session == "" {
		return
	}
	canonical, ok := issuedLocationCanonical(target)
	if !ok {
		return
	}
	host, port, _ := issuedRedirectAuthority(target)
	entry := issuedLocationEntry{url: s.issuedLocationDigest(canonical), authority: s.issuedAuthorityDigest(host, port), scope: scope}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.admitSessionLocked(session)
	entries := s.locations[session]
	for _, existing := range entries {
		if existing == entry {
			s.used[session] = now
			return
		}
	}
	if len(entries) >= issuerCookieMaxEntries {
		entries = entries[1:]
	}
	s.locations[session] = append(entries, entry)
	s.used[session] = now
}

// issuedLocation reports whether the session was delivered exactly this URL
// under a delegation whose scope is still in force.
func (s *issuerQueryStore) issuedLocation(session string, target *url.URL, scopes map[[32]byte]struct{}) bool {
	if s == nil || s.disabled || session == "" || len(scopes) == 0 {
		return false
	}
	canonical, ok := issuedLocationCanonical(target)
	if !ok {
		return false
	}
	digest := s.issuedLocationDigest(canonical)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.locations[session] {
		if _, live := scopes[entry.scope]; live && hmac.Equal(entry.url[:], digest[:]) {
			s.used[session] = time.Now()
			return true
		}
	}
	return false
}

// issuedAuthority reports whether the session was delivered a redirect to any
// URL on this authority under a delegation still in force. It is the evidence a
// CONNECT can see; the inner request must still match a whole URL.
func (s *issuerQueryStore) issuedAuthority(session, host, port string, scopes map[[32]byte]struct{}) bool {
	if s == nil || s.disabled || session == "" || len(scopes) == 0 || host == "" || port == "" {
		return false
	}
	digest := s.issuedAuthorityDigest(canonicalRedirectHost(host), port)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.locations[session] {
		if _, live := scopes[entry.scope]; live && hmac.Equal(entry.authority[:], digest[:]) {
			s.used[session] = time.Now()
			return true
		}
	}
	return false
}

// recordIssuedLocation mints evidence from a delivered redirect. The source is
// the request Pipelock itself sent and the response it received, never a value
// the agent supplied. store is the session's trusted issuer store.
func (ic *InterceptContext) recordIssuedLocation(store *issuerQueryStore, session string, response *http.Response) {
	if ic == nil || ic.Proxy == nil || ic.Config == nil || store == nil ||
		len(ic.Config.FetchProxy.Monitoring.IssuedRedirectDelegations) == 0 {
		return
	}
	target, ok := issuedRedirectLocation(response, ic.Config.FetchProxy.Monitoring.MaxURLLength)
	if !ok {
		return
	}
	now := time.Now()
	for _, d := range ic.Proxy.issuedRedirects(ic.Config, now) {
		if d.admits(response.Request, target) {
			store.rememberIssuedLocation(session, target, d.scope, now)
		}
	}
}

// issuedLocationAllowed reports whether the session's evidence names exactly
// the request URL under a delegation in force.
func (ic *InterceptContext) issuedLocationAllowed(store *issuerQueryStore, session string, target *url.URL) bool {
	if ic == nil || ic.Proxy == nil || store == nil || len(ic.Config.FetchProxy.Monitoring.IssuedRedirectDelegations) == 0 {
		return false
	}
	scopes := issuedRedirectScopes(ic.Proxy.issuedRedirects(ic.Config, time.Now()))
	return store.issuedLocation(session, target, scopes)
}

// withIssuedLocationAllowance relieves only entropy, and only for the values of
// target itself: its whole escaped path, its own query values, and its host's
// heuristic subdomain finding. Query-key entropy and every other check run
// unchanged. used reports whether any relief was consulted and granted.
func withIssuedLocationAllowance(ctx context.Context, target *url.URL, used *atomic.Bool) context.Context {
	host, _, _ := issuedRedirectAuthority(target)
	path := target.EscapedPath()
	query := target.Query()
	ctx = scanner.WithIssuerHostAllowance(ctx, func(candidate string) bool {
		if host == "" || canonicalRedirectHost(candidate) != host {
			return false
		}
		used.Store(true)
		return true
	})
	ctx = scanner.WithIssuerPathAllowance(ctx, func(escaped string) bool {
		if escaped != path {
			return false
		}
		used.Store(true)
		return true
	})
	return scanner.WithIssuerQueryAllowance(ctx, func(key, value string) bool {
		if !slices.Contains(query[key], value) {
			return false
		}
		used.Store(true)
		return true
	})
}

// entropyFinding reports whether a URL result is a heuristic entropy finding,
// the only kind a delegation can relieve. Structural hostname-exfiltration
// findings and every other scanner are never relieved.
func entropyFinding(result scanner.Result) bool {
	return !result.Allowed && result.IsEntropyOnly() &&
		(result.Scanner == scanner.ScannerEntropy || result.Scanner == scanner.ScannerSubdomainEntropy)
}

// fetchIssuedRedirectContext is the fetch transport's own proof. Fetch follows
// the redirect itself, so the response that produced this hop is in hand: it is
// the response of a request Pipelock sent, and its single Location must be the
// URL being followed. No stored state and no TLS interception are involved.
func (p *Proxy) fetchIssuedRedirectContext(ctx context.Context, cfg *config.Config, req *http.Request) (context.Context, *atomic.Bool, bool) {
	if p == nil || cfg == nil || req == nil || req.Response == nil || len(cfg.FetchProxy.Monitoring.IssuedRedirectDelegations) == 0 {
		return ctx, nil, false
	}
	target, ok := issuedRedirectLocation(req.Response, cfg.FetchProxy.Monitoring.MaxURLLength)
	if !ok {
		return ctx, nil, false
	}
	want, ok := issuedLocationCanonical(target)
	if !ok {
		return ctx, nil, false
	}
	if got, ok := issuedLocationCanonical(req.URL); !ok || got != want {
		return ctx, nil, false
	}
	for _, d := range p.issuedRedirects(cfg, time.Now()) {
		if d.admits(req.Response.Request, target) {
			used := &atomic.Bool{}
			return withIssuedLocationAllowance(ctx, req.URL, used), used, true
		}
	}
	return ctx, nil, false
}

// connectIssuedHostContext is the CONNECT-time view of a delegated redirect:
// the tunnel's host and port, not the URL inside it. It relieves only the
// heuristic subdomain finding, only for a destination that both the request's
// snapshot and the live policy will intercept (a passthrough tunnel is opaque,
// so nothing it carries could be matched to an issued URL), and only for the
// session the redirect was delivered to.
func (p *Proxy) connectIssuedHostContext(ctx context.Context, cfg *config.Config, host, port, agent, clientIP string, auth envelope.ActorAuth) (context.Context, *atomic.Bool, bool) {
	if p == nil || cfg == nil || len(cfg.FetchProxy.Monitoring.IssuedRedirectDelegations) == 0 {
		return ctx, nil, false
	}
	live := p.cfgPtr.Load()
	if live == nil || !cfg.TLSInterception.Enabled || !live.TLSInterception.Enabled ||
		isPassthrough(host, cfg.TLSInterception.PassthroughDomains) || isPassthrough(host, live.TLSInterception.PassthroughDomains) ||
		!p.stateIdentityConfigCurrent(cfg, auth) {
		return ctx, nil, false
	}
	ic := &InterceptContext{Proxy: p, Config: cfg, Agent: agent, ClientIP: clientIP, ActorAuth: auth, IssuerRuntime: p.issuerCookieRuntime.Load()}
	store := ic.issuerQueryStore()
	if store == nil {
		return ctx, nil, false
	}
	scopes := issuedRedirectScopes(p.issuedRedirects(cfg, time.Now()))
	if !store.issuedAuthority(sessionKeyFor(cfg, agent, clientIP, auth), host, port, scopes) {
		return ctx, nil, false
	}
	want := canonicalRedirectHost(host)
	used := &atomic.Bool{}
	return scanner.WithIssuerHostAllowance(ctx, func(candidate string) bool {
		if canonicalRedirectHost(candidate) != want {
			return false
		}
		used.Store(true)
		return true
	}), used, true
}
