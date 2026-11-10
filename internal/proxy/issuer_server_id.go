// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"hash"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"golang.org/x/net/http/httpguts"
)

// A server-issued ID is an opaque object identifier an origin returned in a
// JSON response, such as a mail filter or message ID, that the agent then
// names as one segment of a URL path back to that same origin. The path
// entropy gate reads such an ID as a possible payload. It is relieved for one
// segment only when the origin introduced the value before this session sent
// it to that host. Using an allowed ID retains that ordering in send history.
// A string the agent sent first and the origin returned is a reflection, not
// an issue, so it stays scored.
//
// Evidence is in-memory and session-bound like the rest of the issuer store.
// Incomplete outgoing history freezes learning for that caller/destination,
// while established exact proofs remain usable. Unknown destinations freeze
// caller-wide learning. Neither case admits new values from missing history.

const (
	issuerQueryServerID issuerQueryKind = "server_issued_id"

	// An ID shorter than this is never scored as high entropy, and a longer
	// one is not a plausible object identifier.
	issuerServerIDMinLen = 16
	issuerServerIDMaxLen = 512
	// issuerServerIDMaxPerResponse bounds the IDs one response can mint.
	issuerServerIDMaxPerResponse = 512
	// issuerSentMaxEntries bounds the sent-token digests kept per destination.
	// Evicting one would let that token be minted later, so a full set stops
	// learning for that destination instead.
	issuerSentMaxEntries = 8192
	// issuerSentMaxTokensPerRequest bounds the input tokens one request
	// records. Repeated tokens still count toward this workload limit even
	// when their digest needs only one retained history entry.
	issuerSentMaxTokensPerRequest = 4096
	// issuerUnreadableMaxSessions bounds retained ID-history buckets, including
	// incomplete-history tombstones. It bounds callers and destination buckets
	// separately. Admission permanently closes on the first capacity refusal.
	issuerUnreadableMaxSessions = 4096
	// issuerSentAllMaxEntries bounds the total sent digests across buckets.
	// An addition past it freezes only the destination making that addition.
	issuerSentAllMaxEntries = 1 << 17
)

// RFC 3986 sections 2.2 and 3.3: literal pchar punctuation is sub-delims plus
// ':' and '@'. Percent escapes are handled by URL parsing, not admitted as
// literal ID bytes. The same alphabet applies to every origin.
const issuerIDDelimiters = "!$&'()*+,;=:@"

// Only explicit server-first history preserves introduction. An existing
// unknown or agent-first entry cannot acquire it from a later response or use.
type issuerSentProvenance uint8

const (
	issuerSentAgentFirst issuerSentProvenance = iota
	issuerSentServerFirst
)

// issuerServerIDShaped reports whether value can name one literal ASCII URL
// path segment. Slashes, escapes, whitespace and controls cannot occur, so the
// ID is the same string as written and decoded. Shape alone grants nothing.
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
	return issuerSentWordByte(c) || strings.IndexByte(issuerIDDelimiters, c) >= 0
}

// issuerSentWordByte preserves the unreserved/base64 token boundaries used
// by the original input-work budget. Supporting more URI punctuation must
// not change how many input tokens an existing request consumes.
func issuerSentWordByte(c byte) bool {
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

// issuerSentTokens records input words under the original workload budget.
// The same tokenization checks whether a response introduces a new word.
func issuerSentTokens(text string, emit func(string) bool) bool {
	start := -1
	for i := 0; i < len(text); i++ {
		if issuerSentWordByte(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if !emitSentFormRun(text[start:i], emit) {
				return false
			}
			start = -1
		}
	}
	if start >= 0 {
		return emitSentFormRun(text[start:], emit)
	}
	return true
}

// emitSentFormRun records one run, and each side of every "=" in it:
// "=" is an ID character (base64 padding) and also the form key/value
// separator, so "payload=<value>" must record <value> on its own.
func emitSentFormRun(run string, emit func(string) bool) bool {
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

func issuerSentHost(target *url.URL) string {
	if target == nil {
		return ""
	}
	return canonicalRedirectHost(target.Hostname())
}

func (s *issuerQueryStore) originDigest(tag string, target *url.URL, value string) ([32]byte, bool) {
	host, port, ok := issuerCookieOrigin(target)
	if !ok {
		return [32]byte{}, false
	}
	return s.digestFields(tag, strings.ToLower(target.Scheme), canonicalRedirectHost(host), port, value), true
}

// newObservedIssuerQueryStore joins issuer-history transitions to the proxy's
// existing operational audit and metrics. Neither sink receives hosts or IDs.
func (p *Proxy) newObservedIssuerQueryStore() *issuerQueryStore {
	s := newIssuerQueryStore()
	s.observeIDBlock = func(scope string, log bool) {
		p.metrics.RecordIssuerIDBlock(scope)
		if log && p.logger != nil {
			p.logger.LogAnomaly(audit.NewMethodLogContext("ISSUER_ID"), "",
				"server-issued ID evidence blocked ("+scope+"); new learning is frozen for the affected destination (or caller when unknown); known exact IDs remain usable; only a restart resets history, and it also discards every known ID (disabling issuer evidence discards known IDs but keeps history); additional transitions are counted in pipelock_issuer_id_blocks_total", 0)
		}
	}
	return s
}

// recordSent records every token a request carries to its origin: path
// segments, query keys and values, and the body, both raw and decoded. A
// body that was sent but not buffered, or a request over the bound, marks the
// destination unreadable.
func (s *issuerQueryStore) recordSent(session string, target *url.URL, header http.Header, body []byte, bodyKnown bool, _ time.Time) {
	if s == nil || s.disabled || session == "" {
		return
	}
	if target == nil || issuerSentHost(target) == "" {
		s.mu.Lock()
		s.freezeIDCallerLocked(session)
		s.mu.Unlock()
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
	var inputTokens int
	seenTokens := make(map[string]struct{})
	mac := hmac.New(sha256.New, s.key[:])
	host := issuerSentHost(originTarget)
	overflow := false
	recordToken := func(token string) bool {
		if inputTokens >= issuerSentMaxTokensPerRequest {
			overflow = true
			return false
		}
		inputTokens++
		if _, exists := seenTokens[token]; exists {
			return true
		}
		seenTokens[token] = struct{}{}
		digests = append(digests, issuerDigestFields(mac, "sent_host", host, token))
		return true
	}
	for _, text := range texts {
		if !issuerSentTokens(text, recordToken) {
			break
		}
	}
	// Digest each distinct ID-shaped path segment before locking, so that
	// holding s.mu costs one map lookup per candidate rather than HMAC work.
	// Incomplete requests cannot use provenance, so skip this additional work
	// after the existing request-token bound or an unread body is known.
	var pathIDs []issuerPathIDCandidate
	if bodyKnown && !overflow {
		seenSegments := make(map[string]struct{})
		for _, segment := range strings.Split(target.Path, "/") {
			if _, seen := seenSegments[segment]; seen {
				continue
			}
			candidates := s.serverIDCandidates(mac, originTarget, segment)
			if candidates.n == 0 {
				continue
			}
			seenSegments[segment] = struct{}{}
			var words [][32]byte
			_ = issuerSentTokens(segment, func(token string) bool {
				words = append(words, issuerDigestFields(mac, "sent_host", host, token))
				return true
			})
			pathIDs = append(pathIDs, issuerPathIDCandidate{ids: candidates, words: words})
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := s.admitIDDestinationLocked(session, originTarget)
	if bucket == nil || bucket.block != issuerHistoryComplete {
		return
	}
	if !bodyKnown {
		s.freezeIDDestinationLocked(bucket, issuerHistoryUnreadBody)
		return
	}
	if overflow {
		s.freezeIDDestinationLocked(bucket, issuerHistoryRequestLimit)
		return
	}
	// Determine provenance while holding the same lock as history insertion.
	// Only an exact, currently allowed path ID (or its addressing delimiter)
	// can preserve server-first words. This adds flags to tokens already being
	// recorded, never entries at mint time or authority from arbitrary bodies.
	// A retired generation's allowances were revoked, so its sends are all
	// agent-first in the shared ledger.
	serverFirst := make(map[[32]byte]struct{})
	if s.retired {
		pathIDs = nil
	}
	for _, pathID := range pathIDs {
		if s.serverIDMatchLocked(session, pathID.ids) == nil {
			continue
		}
		for _, word := range pathID.words {
			serverFirst[word] = struct{}{}
		}
	}
	sent := bucket.sent
	for _, digest := range digests {
		if _, exists := sent[digest]; exists {
			continue
		}
		if len(sent) >= issuerSentMaxEntries {
			s.freezeIDDestinationLocked(bucket, issuerHistoryDestinationLimit)
			return
		}
		if s.sentEntries >= issuerSentAllMaxEntries {
			s.freezeIDDestinationLocked(bucket, issuerHistoryTotalLimit)
			return
		}
		provenance := issuerSentAgentFirst
		if _, introduced := serverFirst[digest]; introduced {
			provenance = issuerSentServerFirst
		}
		sent[digest] = provenance
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
// the session sent it first or its sent traffic is unreadable.
func (s *issuerQueryStore) mintServerID(session string, target *url.URL, value string, _ time.Time) {
	if s == nil || s.disabled || session == "" || !issuerServerIDShaped(value) {
		return
	}
	if _, _, ok := issuerCookieOrigin(target); !ok {
		return
	}
	// Canonicalize the host and derive every digest before taking the shared
	// lock; IDNA lookup and HMAC work would otherwise serialize all callers.
	host := issuerSentHost(target)
	if host == "" {
		return
	}
	sentDigest := s.digestFields("sent_host", host, value)
	destinationKey := s.idDestinationKey(host)
	idDigest, _ := s.originDigest("server_id", target, value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired {
		return
	}
	issued := s.ids[session]
	if issued != nil {
		if entry, exists := issued.entries[idDigest]; exists {
			issued.touch(entry)
			return
		}
	}
	bucket := s.learningDestinationLocked(session, destinationKey)
	if bucket == nil {
		return
	}
	if provenance, sent := bucket.sent[sentDigest]; sent && provenance != issuerSentServerFirst {
		return
	}
	if !s.idIntroducedLocked(bucket, host, value) {
		return
	}
	if issued == nil {
		issued = newIssuerIDCache()
		s.ids[session] = issued
	}
	if len(issued.entries) >= issuerCookieMaxEntries {
		// Evict only a destination that can still learn. Frozen proofs cannot
		// be replaced, so a full cache of pinned proofs refuses new IDs.
		// learningDestinationLocked above already required a learning caller.
		victim := issued.leastRecentReplaceable()
		if victim == nil {
			return
		}
		issued.remove(victim)
	}
	entry := &issuerIDEntry{digest: idDigest, destination: bucket}
	issued.entries[idDigest] = entry
	issued.touch(entry)
}

// issuerServerIDIntroducible reports whether value carries any word that
// idIntroducedLocked could count as an introduction. A shaped string with none
// (an ISO timestamp, for one) can never mint, so it must not spend the
// per-response mint budget that later IDs in the same listing need.
func issuerServerIDIntroducible(value string) bool {
	found := false
	_ = issuerSentTokens(value, func(string) bool {
		found = true
		return false
	})
	return found
}

// idIntroducedLocked requires an eligible word that is unsent or whose first
// send used an already allowed ID. Agent-first words never become introduction
// proof, including when used inside another issued ID. IDs consisting solely
// of short fields keep ordinary entropy scoring.
func (s *issuerQueryStore) idIntroducedLocked(bucket *issuerIDDestination, host, value string) bool {
	introduced := false
	mac := hmac.New(sha256.New, s.key[:])
	_ = issuerSentTokens(value, func(token string) bool {
		digest := issuerDigestFields(mac, "sent_host", host, token)
		provenance, sent := bucket.sent[digest]
		introduced = !sent || provenance == issuerSentServerFirst
		return !introduced
	})
	return introduced
}

// serverIDIssued reports whether the origin in target issued segment to the
// session as an ID. Path-based addressing can append one colon delimiter to
// the ID before a relative path; the delimiter isn't part of the issued ID.
// See https://learn.microsoft.com/en-us/graph/onedrive-addressing-driveitems
// and https://learn.microsoft.com/en-us/graph/api/driveitem-put-content.
// No other punctuation or content is removed; minting still requires a bare ID.
func (s *issuerQueryStore) serverIDIssued(session string, target *url.URL, segment string) bool {
	if s == nil || s.disabled || session == "" {
		return false
	}
	candidates := s.serverIDCandidates(hmac.New(sha256.New, s.key[:]), target, segment)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired {
		return false
	}
	entry := s.serverIDMatchLocked(session, candidates)
	if entry == nil {
		return false
	}
	// Evict inactive IDs rather than a frequently used directory or item.
	s.ids[session].touch(entry)
	return true
}

// issuerIDCandidates holds the allowance digests one path segment can name at
// one origin: the segment itself, and the ID before one addressing colon.
type issuerIDCandidates struct {
	digests [2][32]byte
	n       int
}

// issuerPathIDCandidate pairs a request path segment's allowance digests with
// the sent-history digests of its words.
type issuerPathIDCandidate struct {
	ids   issuerIDCandidates
	words [][32]byte
}

// serverIDCandidates is the one exact matching rule shared by relief and send
// provenance. It reads no store state, so callers compute it before locking.
// A target that is not a valid https origin yields no candidates.
func (s *issuerQueryStore) serverIDCandidates(mac hash.Hash, target *url.URL, segment string) issuerIDCandidates {
	var c issuerIDCandidates
	host, port, ok := issuerCookieOrigin(target)
	if !ok {
		return c
	}
	host = canonicalRedirectHost(host)
	scheme := strings.ToLower(target.Scheme)
	if issuerServerIDShaped(segment) {
		c.digests[c.n] = issuerDigestFields(mac, "server_id", scheme, host, port, segment)
		c.n++
	}
	if relative := strings.TrimSuffix(segment, ":"); relative != segment && issuerServerIDShaped(relative) {
		c.digests[c.n] = issuerDigestFields(mac, "server_id", scheme, host, port, relative)
		c.n++
	}
	return c
}

// serverIDMatchLocked reads existing authority only; the caller holds s.mu
// and verifies runtime eligibility before granting anything.
func (s *issuerQueryStore) serverIDMatchLocked(session string, c issuerIDCandidates) *issuerIDEntry {
	issued := s.ids[session]
	if issued == nil {
		return nil
	}
	for _, digest := range c.digests[:c.n] {
		if entry := issued.entries[digest]; entry != nil {
			return entry
		}
	}
	return nil
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

// reverseIssuerSend is the reverse proxy's admitted caller and the exact body
// it buffered, carried to the transport that sends the rewritten request.
type reverseIssuerSend struct {
	cfg       *config.Config
	agent     string
	clientIP  string
	actorAuth envelope.ActorAuth
	body      []byte
}

// recordIssuerReverseSent records an outgoing reverse-proxy request after
// Director rewrote its URL and any envelope headers were added, so history
// holds what the upstream actually receives. A request asking to upgrade can
// hand the connection to a byte stream Pipelock does not record, so it
// freezes the destination before anything is sent.
func (p *Proxy) recordIssuerReverseSent(req *http.Request) {
	if p == nil || req == nil {
		return
	}
	send, ok := req.Context().Value(ctxKeyReverseIssuerSend).(reverseIssuerSend)
	if !ok {
		return
	}
	if httpguts.HeaderValuesContainsToken(req.Header["Connection"], "Upgrade") {
		p.taintIssuerSessionForStream(send.cfg, send.agent, send.clientIP, send.actorAuth, req.URL)
		return
	}
	p.recordIssuerForwardSent(send.cfg, send.agent, send.clientIP, send.actorAuth, req, send.body)
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
func (p *Proxy) taintIssuerSessionForStream(cfg *config.Config, agent, clientIP string, actorAuth envelope.ActorAuth, target *url.URL) {
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
	if issuerSentHost(target) == "" {
		store.freezeIDCallerLocked(session)
		return
	}
	if bucket := store.admitIDDestinationLocked(session, target); bucket != nil {
		store.freezeIDDestinationLocked(bucket, issuerHistoryStream)
	}
}
