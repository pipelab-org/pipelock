// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

// A server-issued ID is an opaque object identifier an origin returned in a
// JSON response, such as a mail filter or message ID, that the agent then
// names as one segment of a URL path back to that same origin. The path
// entropy gate reads such an ID as a possible payload. It is relieved for one
// segment only when the origin introduced the value: the exact string never
// appeared in anything this session sent to that origin. A string the agent
// sent and the origin stored and returned is a reflection, not an issue, so
// it stays scored.
//
// Evidence is in-memory and session-bound like the rest of the issuer store.
// A session whose sent traffic cannot be fully read stops minting IDs, so a
// value can never be admitted because Pipelock failed to see it go out.

const (
	issuerQueryServerID issuerQueryKind = "server_issued_id"

	// An ID shorter than this is never scored as high entropy, and a longer
	// one is not a plausible object identifier.
	issuerServerIDMinLen = 16
	issuerServerIDMaxLen = 512
	// issuerServerIDMaxPerResponse bounds the IDs one response can mint.
	issuerServerIDMaxPerResponse = 512
	// issuerSentMaxEntries bounds the sent-token digests kept per session.
	// Evicting one would let that token be minted later, so a full set stops
	// minting for the session instead.
	issuerSentMaxEntries = 8192
	// issuerSentMaxTokensPerRequest bounds the tokens one request records. A
	// request over the bound marks the session unreadable.
	issuerSentMaxTokensPerRequest = 4096
	// issuerUnreadableMaxSessions bounds retained ID-history buckets, including
	// incomplete-history tombstones. New buckets are refused at capacity.
	issuerUnreadableMaxSessions = 4096
	// issuerSentAllMaxEntries bounds the total sent digests across buckets.
	// An addition past it taints only the bucket making that addition.
	issuerSentAllMaxEntries = 1 << 17
)

// issuerServerIDShaped reports whether value can be one whole URL path
// segment naming an object: unreserved characters plus the base64 padding
// and plus signs some providers keep in IDs. No separator, escape or space
// can occur, so the value is the segment exactly as written and as decoded.
func issuerServerIDShaped(value string) bool {
	if len(value) < issuerServerIDMinLen || len(value) > issuerServerIDMaxLen {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !issuerServerIDByte(value[i]) {
			return false
		}
	}
	return true
}

func issuerServerIDByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '_', '.', '~', '=', '+':
		return true
	}
	return false
}

// issuerSentTokens splits text into maximal runs of ID characters and keeps
// those long enough to be minted. Every way a value could later come back as
// an ID is a run of these characters, so recording runs covers the value
// whatever surrounds it.
func issuerSentTokens(text string, emit func(string) bool) bool {
	start := -1
	for i := 0; i < len(text); i++ {
		if issuerServerIDByte(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if !emitSentRun(text[start:i], emit) {
				return false
			}
			start = -1
		}
	}
	if start >= 0 {
		return emitSentRun(text[start:], emit)
	}
	return true
}

// emitSentRun records one maximal run, and each side of every "=" in it:
// "=" is an ID character (base64 padding) and also the form key/value
// separator, so "payload=<value>" must record <value> on its own.
func emitSentRun(run string, emit func(string) bool) bool {
	if len(run) >= issuerServerIDMinLen && !emit(run) {
		return false
	}
	if strings.IndexByte(run, '=') >= 0 {
		for _, part := range strings.Split(run, "=") {
			if len(part) >= issuerServerIDMinLen && part != run && !emit(part) {
				return false
			}
		}
	}
	return true
}

// sentDigest binds a sent token to the host alone. A value sent to a host over
// any scheme or port has reached that host, so it must never mint as an ID
// the host issued, whatever port the ID is later used on.
func (s *issuerQueryStore) sentDigest(target *url.URL, value string) ([32]byte, bool) {
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if host == "" {
		return [32]byte{}, false
	}
	return s.digestFields("sent_host", host, value), true
}

func (s *issuerQueryStore) originDigest(tag string, target *url.URL, value string) ([32]byte, bool) {
	host, port, ok := issuerCookieOrigin(target)
	if !ok {
		return [32]byte{}, false
	}
	return s.digestFields(tag, strings.ToLower(target.Scheme), host, port, value), true
}

// admitIDSessionLocked retains history without eviction. An unremembered
// caller cannot mint: refusing new buckets at capacity preserves both the
// negative evidence and the allowances of existing callers.
func (s *issuerQueryStore) admitIDSessionLocked(session string) bool {
	if _, exists := s.sent[session]; exists {
		return true
	}
	if len(s.sent) >= issuerUnreadableMaxSessions {
		if !s.idCapacityReported && s.observeIDBlock != nil {
			s.observeIDBlock(metrics.IssuerIDBlockCapacity, true)
		}
		s.idCapacityReported = true
		return false
	}
	s.sent[session] = make(map[[32]byte]struct{})
	return true
}

// taintSentLocked revokes only this caller's IDs when its outgoing history
// is incomplete. Neither hosts nor other callers acquire this taint.
func (s *issuerQueryStore) taintSentLocked(session string) {
	if !s.admitIDSessionLocked(session) || s.sentUnreadable[session] {
		return
	}
	delete(s.ids, session)
	s.sentUnreadable[session] = true
	if s.observeIDBlock != nil {
		s.observeIDBlock(metrics.IssuerIDBlockSession, !s.idBlockReported)
	}
	s.idBlockReported = true
}

// newObservedIssuerQueryStore joins issuer-history transitions to the proxy's
// existing operational audit and metrics. Neither sink receives hosts or IDs.
func (p *Proxy) newObservedIssuerQueryStore() *issuerQueryStore {
	s := newIssuerQueryStore()
	s.observeIDBlock = func(scope string, log bool) {
		p.metrics.RecordIssuerIDBlock(scope)
		if log && p.logger != nil {
			p.logger.LogAnomaly(audit.NewMethodLogContext("ISSUER_ID"), "",
				"server-issued ID evidence blocked ("+scope+"); affected caller buckets retain path entropy enforcement; restart or disable and re-enable issuer evidence to clear IDs and history; additional caller transitions are counted in pipelock_issuer_id_blocks_total", 0)
		}
	}
	return s
}

// mintBlockedLocked only inspects history established by send recording.
// Neither a response nor a lookup can turn missing history into authority.
func (s *issuerQueryStore) mintBlockedLocked(session string, target *url.URL) bool {
	_, ok := s.sentDigest(target, "")
	return !ok || s.sent[session] == nil || s.sentUnreadable[session]
}

// recordSent records every token a request carries to its origin: path
// segments, query keys and values, and the body, both raw and decoded. A
// body that was sent but not buffered, or a request over the bound, marks the
// session unreadable.
func (s *issuerQueryStore) recordSent(session string, target *url.URL, header http.Header, body []byte, bodyKnown bool, _ time.Time) {
	if s == nil || s.disabled || session == "" || target == nil {
		return
	}
	// issuerCookieOrigin rejects userinfo so a user:pass@host URL cannot
	// impersonate another origin. The client still sends that userinfo, as
	// Basic auth, to the host. Record against the host with the userinfo
	// removed, and record the user and password as sent text.
	originTarget := target
	if target.User != nil {
		stripped := *target
		stripped.User = nil
		originTarget = &stripped
	}
	if scheme := strings.ToLower(originTarget.Scheme); (scheme != "https" && scheme != "http") || originTarget.Hostname() == "" {
		return
	}
	var texts []string
	texts = append(texts, target.EscapedPath(), target.Path)
	if user := target.User; user != nil {
		texts = appendFormLike(texts, user.Username())
		if password, ok := user.Password(); ok {
			texts = appendFormLike(texts, password)
		}
	}
	texts = appendFormLike(texts, target.RawQuery)
	for name, values := range header {
		texts = append(texts, name)
		for _, value := range values {
			texts = appendFormLike(texts, value)
		}
	}
	if len(body) > 0 {
		texts = appendFormLike(texts, string(body))
	}

	var digests [][32]byte
	overflow := false
	for _, text := range texts {
		complete := issuerSentTokens(text, func(token string) bool {
			if len(digests) >= issuerSentMaxTokensPerRequest {
				overflow = true
				return false
			}
			if digest, ok := s.sentDigest(originTarget, token); ok {
				digests = append(digests, digest)
			}
			return true
		})
		if !complete {
			break
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.admitIDSessionLocked(session) || s.sentUnreadable[session] {
		return
	}
	if !bodyKnown || overflow {
		s.taintSentLocked(session)
		return
	}
	sent := s.sent[session]
	for _, digest := range digests {
		if _, exists := sent[digest]; exists {
			continue
		}
		if len(sent) >= issuerSentMaxEntries || s.sentEntries >= issuerSentAllMaxEntries {
			s.taintSentLocked(session)
			return
		}
		sent[digest] = struct{}{}
		s.sentEntries++
	}
}

// lenientUnescape percent-decodes every valid %XX escape and keeps any
// malformed one as written, so one bad escape cannot hide the rest. plus
// selects whether "+" also decodes to a space, as in a form body.
func lenientUnescape(text string, plus bool) string {
	if strings.IndexByte(text, '%') < 0 && (!plus || strings.IndexByte(text, '+') < 0) {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '%' && i+2 < len(text) && isHex(text[i+1]) && isHex(text[i+2]) {
			b.WriteByte(unhex(text[i+1])<<4 | unhex(text[i+2]))
			i += 2
			continue
		}
		if c == '+' && plus {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// appendFormLike adds text as written, leniently percent-decoded both with
// and without "+" as a space, and each key and value of it read as
// "&"/";"-separated form pairs, decoded the same way. Any of those forms may
// be the one an origin stores and returns.
func appendFormLike(texts []string, text string) []string {
	staged := []string{text, lenientUnescape(text, false), lenientUnescape(text, true)}
	for _, pair := range strings.FieldsFunc(text, func(r rune) bool { return r == '&' || r == ';' }) {
		key, value, _ := strings.Cut(pair, "=")
		for _, part := range []string{key, value} {
			staged = append(staged, lenientUnescape(part, false), lenientUnescape(part, true))
		}
	}
	// Identical copies (a body with no escapes) are one text. Walking each
	// copy would count the same tokens against the per-request cap.
	seen := make(map[string]struct{}, len(staged))
	for _, form := range staged {
		if _, ok := seen[form]; ok {
			continue
		}
		seen[form] = struct{}{}
		texts = append(texts, form)
		texts = appendJSONStringsIfValid(texts, form)
	}
	return texts
}

// appendJSONStringsIfValid walks text when it is a JSON value. A form field,
// query value or header often carries a JSON object whose strings are escaped;
// the raw token scan cannot see through those escapes.
func appendJSONStringsIfValid(texts []string, text string) []string {
	if text == "" || !json.Valid([]byte(text)) {
		return texts
	}
	return appendJSONStrings(texts, []byte(text))
}

// appendJSONStrings adds every string key and value of a JSON body, decoded,
// so an escape sequence in the body cannot hide a token from the raw scan.
func appendJSONStrings(texts []string, body []byte) []string {
	if !json.Valid(body) {
		return texts
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	for {
		token, err := decoder.Token()
		if err != nil {
			return texts
		}
		if s, ok := token.(string); ok {
			texts = append(texts, s)
		}
	}
}

// mintServerID records value as an ID the origin in target issued, unless
// the session sent that exact value to the origin or its sent traffic is
// unreadable.
func (s *issuerQueryStore) mintServerID(session string, target *url.URL, value string, _ time.Time) {
	if s == nil || s.disabled || session == "" || !issuerServerIDShaped(value) {
		return
	}
	if _, _, ok := issuerCookieOrigin(target); !ok {
		return
	}
	sentDigest, ok := s.sentDigest(target, value)
	if !ok {
		return
	}
	idDigest, _ := s.originDigest("server_id", target, value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mintBlockedLocked(session, target) {
		return
	}
	if _, reflected := s.sent[session][sentDigest]; reflected {
		return
	}
	issued := s.ids[session]
	for _, existing := range issued {
		if hmac.Equal(existing[:], idDigest[:]) {
			return
		}
	}
	if len(issued) >= issuerCookieMaxEntries {
		issued = issued[1:]
	}
	s.ids[session] = append(issued, idDigest)
}

// serverIDIssued reports whether the origin in target issued segment to the
// session as an ID. Path-based addressing can append one colon delimiter to
// the ID before a relative path; the delimiter isn't part of the issued ID.
// See https://learn.microsoft.com/en-us/graph/onedrive-addressing-driveitems
// and https://learn.microsoft.com/en-us/graph/api/driveitem-put-content.
// No other punctuation or content is removed; minting still requires a bare ID.
func (s *issuerQueryStore) serverIDIssued(session string, target *url.URL, segment string) bool {
	segment = strings.TrimSuffix(segment, ":")
	if s == nil || s.disabled || session == "" || !issuerServerIDShaped(segment) {
		return false
	}
	digest, ok := s.originDigest("server_id", target, segment)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mintBlockedLocked(session, target) {
		return false
	}
	for _, existing := range s.ids[session] {
		if hmac.Equal(existing[:], digest[:]) {
			return true
		}
	}
	return false
}

// recordIssuerRequestSent records what an allowed request is about to send
// upstream. It runs before forwarding, so a response to a later request can
// never mint a value this request carried, even when the two overlap.
func recordIssuerRequestSent(ic *InterceptContext, r *http.Request, body []byte) {
	if ic == nil || ic.Proxy == nil || !ic.ActorAuth.TrustedForIdentity() || r == nil || r.URL == nil {
		return
	}
	// Trusted callers record into the live store even when an enabled reload
	// replaced a tunnel's snapshot. Untrusted callers never mutate this state.
	store := ic.Proxy.issuerStoreForUnmediatedSend()
	if store == nil {
		return
	}
	bodyKnown := body != nil || r.Body == nil || r.Body == http.NoBody
	session := sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
	store.recordSent(session, r.URL, r.Header, body, bodyKnown, time.Now())
}

// issuerStoreForUnmediatedSend returns the live issuer store whatever
// configuration snapshot the trusted sender holds. Callers must check the
// resolved actor grade before accessing it. This grants no allowance.
func (p *Proxy) issuerStoreForUnmediatedSend() *issuerQueryStore {
	if p == nil {
		return nil
	}
	runtime := p.issuerCookieRuntime.Load()
	if runtime == nil {
		return nil
	}
	return runtime.query
}

// recordIssuerForwardSent records a plain-HTTP forward-proxy request as sent.
// A body Pipelock did not buffer stops minting for the session.
func (p *Proxy) recordIssuerForwardSent(cfg *config.Config, agent, clientIP string, actorAuth envelope.ActorAuth, r *http.Request, body []byte) {
	if !actorAuth.TrustedForIdentity() {
		return
	}
	store := p.issuerStoreForUnmediatedSend()
	if store == nil || r == nil || r.URL == nil {
		return
	}
	bodyKnown := body != nil || r.Body == nil || r.Body == http.NoBody
	store.recordSent(sessionKeyFor(cfg, agent, clientIP, actorAuth), r.URL, r.Header, body, bodyKnown, time.Now())
}

// recordIssuerFetchSent records a /fetch request's URL as sent. It carries no
// body, so its tokens are complete.
func (p *Proxy) recordIssuerFetchSent(cfg *config.Config, agent, clientIP string, actorAuth envelope.ActorAuth, target *url.URL) {
	if !actorAuth.TrustedForIdentity() {
		return
	}
	store := p.issuerStoreForUnmediatedSend()
	if store == nil || target == nil {
		return
	}
	store.recordSent(sessionKeyFor(cfg, agent, clientIP, actorAuth), target, nil, nil, true, time.Now())
}

// taintIssuerSessionForStream marks a session whose traffic now includes a
// stream Pipelock does not record token by token, such as WebSocket frames.
func (p *Proxy) taintIssuerSessionForStream(cfg *config.Config, agent, clientIP string, actorAuth envelope.ActorAuth, _ *url.URL) {
	if !actorAuth.TrustedForIdentity() {
		return
	}
	store := p.issuerStoreForUnmediatedSend()
	if store == nil || store.disabled {
		return
	}
	session := sessionKeyFor(cfg, agent, clientIP, actorAuth)
	if session == "" {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.taintSentLocked(session)
}
