// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net/url"
	"strings"
	"sync"
)

// issuerNumericCardJoinReceiptKey labels a DLP numeric card-join allowance:
// built-in Credit Card Number spans on raw query_concat or query_subsequence
// views where every contributing value is a whole 8-14 digit ASCII number
// introduced server-first by the exact destination HTTPS origin.
const issuerNumericCardJoinReceiptKey = "dlp_issuer_numeric_card_join_allow"

const (
	// issuerQueryNumericCardJoin names the receipt extension value for
	// per-span server-first numeric card-join relief.
	issuerQueryNumericCardJoin issuerQueryKind = "issued_numeric_card_join"

	issuerNumericIDMinLen         = 8
	issuerNumericIDMaxLen         = 14
	issuerNumericIDMaxPerOrigin   = 256
	issuerNumericIDMaxPerResponse = 256
	issuerNumericIDMaxPerSession  = issuerCookieMaxEntries

	issuerNumericSentMaxTokensPerRequest = 4096
	issuerNumericSentMaxEntries          = 8192
	issuerNumericSentAllMaxEntries       = 1 << 17
	issuerNumericMaxBuckets              = 4096
)

// issuerBrowserOrigin returns the exact browser-origin tuple (scheme, host,
// port) for an HTTPS URL without userinfo. Unlike issuerCookieOrigin, host
// preserves any trailing dot, matching urlDigest and browser origin equality.
func issuerBrowserOrigin(u *url.URL) (scheme, host, port string, ok bool) {
	_, port, ok = issuerCookieOrigin(u)
	if !ok {
		return "", "", "", false
	}
	return strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), port, true
}

// isIssuedNumericValue reports whether value matches ^[0-9]{8,14}$.
func isIssuedNumericValue(value string) bool {
	if len(value) < issuerNumericIDMinLen || len(value) > issuerNumericIDMaxLen {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// issuerNumericRuns visits every maximal contiguous ASCII digit run in text
// whose length is in [8, 14]. Runs shorter than 8 or longer than 14 digits are
// never emitted or sliced. Returning false from emit stops the scan early.
func issuerNumericRuns(text string, emit func(string) bool) bool {
	i := 0
	n := len(text)
	for i < n {
		c := text[i]
		if c < '0' || c > '9' {
			i++
			continue
		}
		start := i
		for i < n && text[i] >= '0' && text[i] <= '9' {
			i++
		}
		runLen := i - start
		if runLen >= issuerNumericIDMinLen && runLen <= issuerNumericIDMaxLen {
			if !emit(text[start:i]) {
				return false
			}
		}
	}
	return true
}

// extractHTMLNumericIDs extracts up to limit distinct maximal 8-14 digit runs
// from raw HTML bytes (body text, attributes, and inline scripts), capped at
// issuerQueryMaxHTMLBytes.
func extractHTMLNumericIDs(body []byte, limit int) []string {
	if len(body) == 0 || limit <= 0 {
		return nil
	}
	if len(body) > issuerQueryMaxHTMLBytes {
		end := issuerQueryMaxHTMLBytes
		if body[end] >= '0' && body[end] <= '9' {
			for end > 0 && body[end-1] >= '0' && body[end-1] <= '9' {
				end--
			}
		}
		body = body[:end]
	}
	var out []string
	seen := make(map[string]struct{})
	issuerNumericRuns(string(body), func(run string) bool {
		if _, dup := seen[run]; dup {
			return true
		}
		seen[run] = struct{}{}
		out = append(out, run)
		return len(out) < limit
	})
	return out
}

// issuerNumericLedger is the process-lifetime negative history ledger for
// 8-14 digit numeric tokens. It is separate from issuerIDLedger with its own
// lock and budgets so numeric traffic can never freeze server_issued_id
// learning, while surviving reloads that discard positive generations.
type issuerNumericLedger struct {
	mu              sync.Mutex
	key             [32]byte
	disabled        bool
	history         map[string]*issuerNumericCaller
	destinations    int
	admissionClosed bool
	sentEntries     int
}

type issuerNumericCaller struct {
	block        issuerIDHistoryBlock
	destinations map[[32]byte]*issuerNumericDestination
}

// issuerNumericSentRecord records host-level send history while binding
// server-first provenance strictly to the exact browser origin that issued the
// value. Another origin on the same host (different port, scheme, or
// trailing-dot spelling) cannot inherit server-first provenance.
type issuerNumericSentRecord struct {
	serverFirst       bool
	serverFirstOrigin [32]byte
}

type issuerNumericDestination struct {
	block issuerIDHistoryBlock
	sent  map[[32]byte]issuerNumericSentRecord
}

func newIssuerNumericLedger(reader io.Reader) *issuerNumericLedger {
	l := &issuerNumericLedger{history: make(map[string]*issuerNumericCaller)}
	if _, err := io.ReadFull(reader, l.key[:]); err != nil {
		l.disabled = true
	}
	return l
}

// issuerNumericEntry is one retained server-first numeric proof, linked into
// both its per-origin LRU ring (capped at 256) and its per-session LRU ring
// (capped at issuerNumericIDMaxPerSession).
type issuerNumericEntry struct {
	originKey          [32]byte
	valDigest          [32]byte
	origPrev, origNext *issuerNumericEntry
	sessPrev, sessNext *issuerNumericEntry
}

type issuerNumericOriginLRU struct {
	entries map[[32]byte]*issuerNumericEntry
	order   issuerNumericEntry
}

func newIssuerNumericOriginLRU() *issuerNumericOriginLRU {
	o := &issuerNumericOriginLRU{entries: make(map[[32]byte]*issuerNumericEntry)}
	o.order.origPrev, o.order.origNext = &o.order, &o.order
	return o
}

func (o *issuerNumericOriginLRU) unlink(e *issuerNumericEntry) {
	if e.origNext == nil {
		return
	}
	e.origPrev.origNext, e.origNext.origPrev = e.origNext, e.origPrev
	e.origPrev, e.origNext = nil, nil
}

func (o *issuerNumericOriginLRU) pushFront(e *issuerNumericEntry) {
	o.unlink(e)
	e.origPrev, e.origNext = &o.order, o.order.origNext
	o.order.origNext.origPrev = e
	o.order.origNext = e
}

type issuerNumericCache struct {
	byOrigin     map[[32]byte]*issuerNumericOriginLRU
	sessionOrder issuerNumericEntry
	total        int
}

func newIssuerNumericCache() *issuerNumericCache {
	c := &issuerNumericCache{byOrigin: make(map[[32]byte]*issuerNumericOriginLRU)}
	c.sessionOrder.sessPrev, c.sessionOrder.sessNext = &c.sessionOrder, &c.sessionOrder
	return c
}

func (c *issuerNumericCache) unlinkSession(e *issuerNumericEntry) {
	if e.sessNext == nil {
		return
	}
	e.sessPrev.sessNext, e.sessNext.sessPrev = e.sessNext, e.sessPrev
	e.sessPrev, e.sessNext = nil, nil
}

func (c *issuerNumericCache) pushSessionFront(e *issuerNumericEntry) {
	c.unlinkSession(e)
	e.sessPrev, e.sessNext = &c.sessionOrder, c.sessionOrder.sessNext
	c.sessionOrder.sessNext.sessPrev = e
	c.sessionOrder.sessNext = e
}

func (c *issuerNumericCache) touch(origin *issuerNumericOriginLRU, e *issuerNumericEntry) {
	origin.pushFront(e)
	c.pushSessionFront(e)
}

func (c *issuerNumericCache) remove(e *issuerNumericEntry) {
	if origin := c.byOrigin[e.originKey]; origin != nil {
		origin.unlink(e)
		delete(origin.entries, e.valDigest)
		if len(origin.entries) == 0 {
			delete(c.byOrigin, e.originKey)
		}
	}
	c.unlinkSession(e)
	c.total--
}

func (c *issuerNumericCache) put(originKey, valDigest [32]byte) {
	origin := c.byOrigin[originKey]
	if origin != nil {
		if existing := origin.entries[valDigest]; existing != nil {
			c.touch(origin, existing)
			return
		}
		if len(origin.entries) >= issuerNumericIDMaxPerOrigin {
			if victim := origin.order.origPrev; victim != &origin.order {
				c.remove(victim)
			}
		}
	}
	if c.total >= issuerNumericIDMaxPerSession {
		if victim := c.sessionOrder.sessPrev; victim != &c.sessionOrder {
			c.remove(victim)
		}
	}
	origin = c.byOrigin[originKey]
	if origin == nil {
		origin = newIssuerNumericOriginLRU()
		c.byOrigin[originKey] = origin
	}
	entry := &issuerNumericEntry{originKey: originKey, valDigest: valDigest}
	origin.entries[valDigest] = entry
	c.touch(origin, entry)
	c.total++
}

func (l *issuerNumericLedger) digestFields(fields ...string) [32]byte {
	return issuerDigestFields(hmac.New(sha256.New, l.key[:]), fields...)
}

func (l *issuerNumericLedger) destinationKey(host string) [32]byte {
	return l.digestFields("numeric_destination", host)
}

func (l *issuerNumericLedger) admitCallerLocked(session string) *issuerNumericCaller {
	if caller := l.history[session]; caller != nil {
		return caller
	}
	if l.admissionClosed || len(l.history) >= issuerNumericMaxBuckets {
		l.admissionClosed = true
		return nil
	}
	caller := &issuerNumericCaller{destinations: make(map[[32]byte]*issuerNumericDestination)}
	l.history[session] = caller
	return caller
}

func (l *issuerNumericLedger) admitDestinationLocked(session string, target *url.URL) *issuerNumericDestination {
	host := issuerSentHost(target)
	if host == "" {
		l.freezeCallerLocked(session)
		return nil
	}
	caller := l.admitCallerLocked(session)
	if caller == nil || caller.block != issuerHistoryComplete {
		return nil
	}
	key := l.destinationKey(host)
	if bucket := caller.destinations[key]; bucket != nil {
		return bucket
	}
	if l.admissionClosed || l.destinations >= issuerNumericMaxBuckets {
		l.admissionClosed = true
		return nil
	}
	bucket := &issuerNumericDestination{sent: make(map[[32]byte]issuerNumericSentRecord)}
	caller.destinations[key] = bucket
	l.destinations++
	return bucket
}

func (l *issuerNumericLedger) freezeDestinationLocked(bucket *issuerNumericDestination, reason issuerIDHistoryBlock) {
	if bucket.block != issuerHistoryComplete {
		return
	}
	if reason == issuerHistoryComplete {
		reason = issuerHistoryUnknown
	}
	bucket.block = reason
	l.sentEntries -= len(bucket.sent)
	bucket.sent = nil
}

func (l *issuerNumericLedger) freezeCallerLocked(session string) {
	caller := l.admitCallerLocked(session)
	if caller == nil || caller.block != issuerHistoryComplete {
		return
	}
	caller.block = issuerHistoryUnknownDestination
	for _, bucket := range caller.destinations {
		l.sentEntries -= len(bucket.sent)
		bucket.sent = nil
	}
}

func (l *issuerNumericLedger) learningDestinationLocked(session string, key [32]byte) *issuerNumericDestination {
	caller := l.history[session]
	if caller == nil || caller.block != issuerHistoryComplete {
		return nil
	}
	bucket := caller.destinations[key]
	if bucket == nil || bucket.block != issuerHistoryComplete {
		return nil
	}
	return bucket
}

func (s *issuerQueryStore) numericIDExistsLocked(session string, originKey, valDigest [32]byte) bool {
	cache := s.numericIDs[session]
	if cache == nil {
		return false
	}
	origin := cache.byOrigin[originKey]
	if origin == nil {
		return false
	}
	_, exists := origin.entries[valDigest]
	return exists
}

// recordNumericSent records every 8-14 digit numeric token an outbound request
// carries into the dedicated numeric sent-history ledger. Its caps and freezes
// are completely independent of issuerIDLedger so numeric traffic never freezes
// server_issued_id learning.
func (s *issuerQueryStore) recordNumericSent(session string, originTarget *url.URL, texts []string, bodyKnown bool) {
	if s == nil || s.numericLedger == nil || s.numericLedger.disabled || session == "" {
		return
	}
	l := s.numericLedger
	if originTarget == nil || issuerSentHost(originTarget) == "" {
		l.mu.Lock()
		l.freezeCallerLocked(session)
		l.mu.Unlock()
		return
	}
	if scheme := strings.ToLower(originTarget.Scheme); (scheme != "https" && scheme != "http") || originTarget.Hostname() == "" {
		return
	}
	host := issuerSentHost(originTarget)
	scheme, browserHost, port, validOrigin := issuerBrowserOrigin(originTarget)

	type numericSentToken struct {
		sentDigest [32]byte
		valDigest  [32]byte
	}
	var tokens []numericSentToken
	var originKey [32]byte
	mac := hmac.New(sha256.New, l.key[:])
	if validOrigin {
		originKey = issuerDigestFields(mac, "numeric_origin", scheme, browserHost, port)
	}
	var inputTokens int
	seen := make(map[string]struct{})
	overflow := false
	recordToken := func(token string) bool {
		if inputTokens >= issuerNumericSentMaxTokensPerRequest {
			overflow = true
			return false
		}
		inputTokens++
		if _, dup := seen[token]; dup {
			return true
		}
		seen[token] = struct{}{}
		entry := numericSentToken{
			sentDigest: issuerDigestFields(mac, "numeric_sent_host", host, token),
		}
		if validOrigin && bodyKnown {
			entry.valDigest = issuerDigestFields(mac, "numeric_id", scheme, browserHost, port, token)
		}
		tokens = append(tokens, entry)
		return true
	}
	if bodyKnown {
		for _, text := range texts {
			if !issuerNumericRuns(text, recordToken) {
				break
			}
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	bucket := l.admitDestinationLocked(session, originTarget)
	if bucket == nil || bucket.block != issuerHistoryComplete {
		return
	}
	if !bodyKnown {
		l.freezeDestinationLocked(bucket, issuerHistoryUnreadBody)
		return
	}
	if overflow {
		l.freezeDestinationLocked(bucket, issuerHistoryRequestLimit)
		return
	}
	checkProvenance := validOrigin && !s.numericRetired
	for _, tok := range tokens {
		if _, exists := bucket.sent[tok.sentDigest]; exists {
			continue
		}
		if len(bucket.sent) >= issuerNumericSentMaxEntries {
			l.freezeDestinationLocked(bucket, issuerHistoryDestinationLimit)
			return
		}
		if l.sentEntries >= issuerNumericSentAllMaxEntries {
			l.freezeDestinationLocked(bucket, issuerHistoryTotalLimit)
			return
		}
		var rec issuerNumericSentRecord
		if checkProvenance && s.numericIDExistsLocked(session, originKey, tok.valDigest) {
			rec = issuerNumericSentRecord{
				serverFirst:       true,
				serverFirstOrigin: originKey,
			}
		}
		bucket.sent[tok.sentDigest] = rec
		l.sentEntries++
	}
}

// freezeNumericStream marks a destination (or caller when unknown) as frozen
// in the numeric sent-history ledger after an unrecorded stream such as a
// WebSocket, opaque CONNECT passthrough, or reverse-proxy Upgrade.
func (s *issuerQueryStore) freezeNumericStream(session string, target *url.URL) {
	if s == nil || s.numericLedger == nil || s.numericLedger.disabled || session == "" {
		return
	}
	l := s.numericLedger
	l.mu.Lock()
	defer l.mu.Unlock()
	if issuerSentHost(target) == "" {
		l.freezeCallerLocked(session)
		return
	}
	if bucket := l.admitDestinationLocked(session, target); bucket != nil {
		l.freezeDestinationLocked(bucket, issuerHistoryStream)
	}
}

// mintNumericIDs records up to issuerNumericIDMaxPerResponse distinct 8-14
// digit numeric IDs as issued by target's exact browser origin. Missing or
// frozen numeric sent-history fails closed, and agent-first values never
// become issued.
func (s *issuerQueryStore) mintNumericIDs(session string, target *url.URL, values []string) {
	if s == nil || s.numericLedger == nil || s.numericLedger.disabled || session == "" || len(values) == 0 {
		return
	}
	l := s.numericLedger
	scheme, browserHost, port, ok := issuerBrowserOrigin(target)
	if !ok {
		return
	}
	sentHost := issuerSentHost(target)
	if sentHost == "" {
		return
	}
	type candidate struct {
		sentDigest [32]byte
		valDigest  [32]byte
	}
	mac := hmac.New(sha256.New, l.key[:])
	originKey := issuerDigestFields(mac, "numeric_origin", scheme, browserHost, port)
	destKey := issuerDigestFields(mac, "numeric_destination", sentHost)
	seen := make(map[string]struct{}, min(len(values), issuerNumericIDMaxPerResponse))
	candidates := make([]candidate, 0, min(len(values), issuerNumericIDMaxPerResponse))
	for _, value := range values {
		if !isIssuedNumericValue(value) {
			continue
		}
		if _, dup := seen[value]; dup {
			continue
		}
		seen[value] = struct{}{}
		candidates = append(candidates, candidate{
			sentDigest: issuerDigestFields(mac, "numeric_sent_host", sentHost, value),
			valDigest:  issuerDigestFields(mac, "numeric_id", scheme, browserHost, port, value),
		})
		if len(candidates) >= issuerNumericIDMaxPerResponse {
			break
		}
	}
	if len(candidates) == 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if s.numericRetired {
		return
	}
	bucket := l.learningDestinationLocked(session, destKey)
	if bucket == nil {
		return
	}
	cache := s.numericIDs[session]
	for _, cand := range candidates {
		if rec, sent := bucket.sent[cand.sentDigest]; sent && (!rec.serverFirst || rec.serverFirstOrigin != originKey) {
			continue
		}
		if cache == nil {
			cache = newIssuerNumericCache()
			s.numericIDs[session] = cache
		}
		cache.put(originKey, cand.valDigest)
	}
}

// numericIDsIssued reports whether every value in values (at least two whole
// 8-14 digit numbers) is currently active in the session's server-first
// numeric store for target's exact browser origin. On a full match, all
// matched entries are touched in LRU order.
func (s *issuerQueryStore) numericIDsIssued(session string, target *url.URL, values []string) bool {
	if s == nil || s.numericLedger == nil || s.numericLedger.disabled || session == "" || len(values) < 2 {
		return false
	}
	l := s.numericLedger
	scheme, browserHost, port, ok := issuerBrowserOrigin(target)
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, l.key[:])
	originKey := issuerDigestFields(mac, "numeric_origin", scheme, browserHost, port)
	digests := make([][32]byte, len(values))
	for i, value := range values {
		if !isIssuedNumericValue(value) {
			return false
		}
		digests[i] = issuerDigestFields(mac, "numeric_id", scheme, browserHost, port, value)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if s.numericRetired {
		return false
	}
	cache := s.numericIDs[session]
	if cache == nil {
		return false
	}
	origin := cache.byOrigin[originKey]
	if origin == nil {
		return false
	}
	matched := make([]*issuerNumericEntry, len(digests))
	for i, d := range digests {
		entry := origin.entries[d]
		if entry == nil {
			return false
		}
		matched[i] = entry
	}
	for _, entry := range matched {
		cache.touch(origin, entry)
	}
	return true
}

// issuerNumericCardJoinStaleLayer names the refusal of a request whose numeric
// card-join evidence was revoked between the URL rescan and the upstream send.
const issuerNumericCardJoinStaleLayer = "issuer_numeric_card_join_stale"

// numericReliefCurrent reports whether every value set that relieved a request
// is still issued by the live server-first numeric store.
func numericReliefCurrent(store *issuerQueryStore, session string, target *url.URL, sets [][]string) bool {
	if len(sets) == 0 {
		return false
	}
	for _, values := range sets {
		if !store.numericIDsIssued(session, target, values) {
			return false
		}
	}
	return true
}
