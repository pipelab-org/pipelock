// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Keep replay eviction independent of permissions learned from responses.
const issuerQueryReplayMaxEntries = 256

type issuerQueryReplayStore struct {
	mu       sync.Mutex
	sessions map[string]*issuerQueryReplaySession
}

type issuerQueryReplaySession struct {
	digests  [][32]byte // oldest first
	lastUsed time.Time
}

func nextIssuerQueryReplayStore(old *issuerCookieRuntime, cfg *config.Config, identityGeneration uint64) *issuerQueryReplayStore {
	if !issuerCookieEnabled(cfg) {
		return nil
	}
	if old != nil && old.replay != nil && old.identityGeneration == identityGeneration {
		return old.replay
	}
	return &issuerQueryReplayStore{sessions: make(map[string]*issuerQueryReplaySession)}
}

// touch updates the LRU only on a hit or an admitted response. The caller
// already bound the digest to the exact origin using the issuer HMAC key.
func (s *issuerQueryReplayStore) touch(session string, digest [32]byte, remember bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := s.sessions[session]
	if bucket == nil {
		if !remember {
			return false
		}
		if len(s.sessions) >= issuerCookieMaxSessions {
			var oldest string
			for id, entry := range s.sessions {
				if oldest == "" || entry.lastUsed.Before(s.sessions[oldest].lastUsed) {
					oldest = id
				}
			}
			delete(s.sessions, oldest)
		}
		bucket = &issuerQueryReplaySession{}
		s.sessions[session] = bucket
	}
	i := slices.Index(bucket.digests, digest)
	switch {
	case i >= 0:
		copy(bucket.digests[i:], bucket.digests[i+1:])
		bucket.digests[len(bucket.digests)-1] = digest
	case !remember:
		return false
	case len(bucket.digests) == issuerQueryReplayMaxEntries:
		copy(bucket.digests, bucket.digests[1:])
		bucket.digests[len(bucket.digests)-1] = digest
	default:
		bucket.digests = append(bucket.digests, digest)
	}
	bucket.lastUsed = time.Now()
	return true
}

type issuerQueryReplayScopeKey struct{}

// A scope holds the identity and policy generation resolved at admission.
// Recheck the live runtime both when granting relief and on response receipt.
type issuerQueryReplayScope struct {
	proxy   *Proxy
	runtime *issuerCookieRuntime
	session string
	scheme  string
}

func (p *Proxy) issuerReplayScope(runtime *issuerCookieRuntime, cfg *config.Config, agent, clientIP string, auth envelope.ActorAuth) issuerQueryReplayScope {
	_, projected := stateIdentity(cfg, agent, auth)
	if !projected.TrustedForIdentity() || !issuerCookieEnabled(cfg) || runtime == nil ||
		runtime.replay == nil || runtime.query == nil || runtime.query.disabled {
		return issuerQueryReplayScope{}
	}
	return issuerQueryReplayScope{
		proxy: p, runtime: runtime, session: sessionKeyFor(cfg, agent, clientIP, auth), scheme: schemeHTTP,
	}
}

func (ic *InterceptContext) issuerReplayScope() issuerQueryReplayScope {
	replay := ic.Proxy.issuerReplayScope(ic.currentIssuerRuntime(), ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
	replay.scheme = schemeHTTPS
	return replay
}

func (s issuerQueryReplayScope) current() bool {
	if s.runtime == nil || s.session == "" {
		return false
	}
	live := s.proxy.issuerCookieRuntime.Load()
	return s.runtime.sameEvidenceGeneration(live) && s.runtime.replay == live.replay
}

func (s issuerQueryReplayScope) digest(target *url.URL, value string) ([32]byte, bool) {
	if value == "" || target == nil || target.Scheme != s.scheme || target.User != nil || target.Opaque != "" {
		return [32]byte{}, false
	}
	host, port := strings.ToLower(target.Hostname()), effectiveURLPort(target)
	if host == "" || port == "" {
		return [32]byte{}, false
	}
	return s.runtime.query.digestFields("query_replay", target.Scheme, host, port, value), true
}

// The HTTP Host field can override URL.Host at dispatch. An authority
// mismatch grants no evidence and consumes none on intercepted requests.
func issuerReplayAuthorityMatches(r *http.Request) bool {
	if r.Host == "" || strings.EqualFold(r.Host, r.URL.Host) {
		return true
	}
	wire := &url.URL{Scheme: r.URL.Scheme, Host: r.Host}
	return strings.EqualFold(wire.Hostname(), r.URL.Hostname()) && effectiveURLPort(wire) == effectiveURLPort(r.URL)
}

func (s issuerQueryReplayScope) scanContext(ctx context.Context, target *url.URL, used *bool) context.Context {
	if !s.current() || target.Scheme != s.scheme || target.RawQuery == "" {
		return ctx
	}
	return scanner.WithIssuerQueryReplayAllowance(ctx, func(value string) bool {
		if *used || !s.current() {
			return false
		}
		digest, ok := s.digest(target, value)
		// Malformed or ambiguous input has no single decoded query value.
		if _, err := url.ParseQuery(target.RawQuery); err != nil {
			return false
		}
		*used = ok && s.runtime.replay.touch(s.session, digest, false) && s.current()
		return *used
	})
}

func (s issuerQueryReplayScope) recordResponse(req *http.Request, resp *http.Response) {
	if resp == nil || resp.StatusCode == 0 || !s.current() || !issuerReplayAuthorityMatches(req) {
		return
	}
	if digest, ok := s.digest(req.URL, req.URL.RawQuery); ok {
		s.runtime.replay.touch(s.session, digest, true)
	}
}

type issuerQueryReplayTransport struct {
	next   http.RoundTripper
	replay issuerQueryReplayScope
}

func (t issuerQueryReplayTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(r)
	if err == nil {
		t.replay.recordResponse(r, resp)
	}
	return resp, err
}

// A RoundTrip observes the response before CheckRedirect handles its Location.
// Only the request passed to that RoundTrip can add replay evidence.
func (s issuerQueryReplayScope) forwardClient(client *http.Client) *http.Client {
	if !s.current() {
		return client
	}
	wrapped := *client
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	wrapped.Transport = issuerQueryReplayTransport{next: next, replay: s}
	return &wrapped
}
