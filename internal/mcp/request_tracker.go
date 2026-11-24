// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// maxTrackedRequests caps the number of pending request IDs to prevent
// unbounded memory growth from a compromised client sending requests
// without consuming responses. Same cap pattern as tool baseline (10,000).
const maxTrackedRequests = 10000

// RequestTracker records outbound JSON-RPC request IDs and validates
// that inbound response IDs match a previously tracked request. This
// prevents confused deputy attacks where a malicious MCP server sends
// unsolicited responses with IDs the client never used.
//
// A nil tracker passes all IDs through (feature disabled).
type RequestTracker struct {
	mu      sync.Mutex
	pending map[string]trackedRequest
	// order preserves insertion order for FIFO eviction when cap is reached.
	order []string
	// seeded is true once at least one request ID has been tracked.
	// Validate only rejects unsolicited IDs after the tracker has been seeded,
	// so responses arriving before any request tracking (e.g., during MCP
	// server initialization) pass through instead of being blocked.
	seeded bool
	// strict rejects response envelopes whose ID is absent or null. It is used
	// by HTTP response channels with an exact request set (including an empty
	// set), while ordinary stdio/WS trackers retain JSON-RPC parse-error parity.
	strict bool
	// A late response to one of these IDs could belong to a different
	// admitted call. Keep method correlation, but decline receipt attribution.
	ambiguousIDs          map[string]struct{}
	ambiguityLimitReached bool
}

// TrackedRequestOutcome carries the receipt metadata needed to emit a
// post-response outcome for a previously admitted MCP request.
type TrackedRequestOutcome struct {
	Receipt receipt.EmitOpts
	handle  *mcpOutcomeHandle
	// Method is the JSON-RPC method of the matching request, used by
	// response-side A2A routing (Agent Card vs field-aware body scan).
	Method          string
	ownsNativeLease bool
	// pinned marks a v3 registration that must stay owned until its response
	// correlates: capacity eviction refuses a newcomer instead of evicting it.
	pinned           bool
	readyToCorrelate *atomic.Bool // set at the commit boundary for held v3 sends
}

func (o TrackedRequestOutcome) releaseNativeLease() {
	if o.ownsNativeLease {
		o.Receipt.NativeLease.Release()
	}
}

type requestRegistration struct{ _ byte }

type trackedRequest struct {
	registration            *requestRegistration
	outcome                 TrackedRequestOutcome
	rejectionOutcomeClaimed bool
}

// PendingRequestOutcome is a drained pending JSON-RPC request ID plus its
// outcome receipt metadata.
type PendingRequestOutcome struct {
	ID      json.RawMessage
	Outcome TrackedRequestOutcome
}

// NewRequestTracker creates a tracker with an empty pending set.
func NewRequestTracker() *RequestTracker {
	return &RequestTracker{
		pending: make(map[string]trackedRequest),
	}
}

// NewStrictRequestTracker creates a tracker that rejects response IDs even
// when no request ID is pending. Use it on HTTP response channels where the
// corresponding client request is already known, or where responses are never
// valid, so the initialization race exception cannot become a fail-open.
func NewStrictRequestTracker(ids ...json.RawMessage) *RequestTracker {
	t := NewRequestTracker()
	t.seeded = true
	t.strict = true
	for _, id := range ids {
		t.Track(id)
	}
	return t
}

// NewStrictRequestTrackerFor records a single request ID with its JSON-RPC
// method so the matching response can apply A2A Agent Card controls.
func NewStrictRequestTrackerFor(id json.RawMessage, method string) *RequestTracker {
	t := NewRequestTracker()
	t.seeded = true
	t.strict = true
	t.TrackOutcome(id, TrackedRequestOutcome{Method: method})
	return t
}

// Track records a request ID as pending. Nil/null IDs are ignored
// (notifications don't expect responses). If the pending set exceeds
// maxTrackedRequests, the oldest entry is evicted.
func (t *RequestTracker) Track(id json.RawMessage) {
	t.TrackOutcome(id, TrackedRequestOutcome{})
}

// TrackRequest records a request ID together with its JSON-RPC method so the
// matching response can route A2A Agent Card checks without shape heuristics.
func (t *RequestTracker) TrackRequest(id json.RawMessage, method string) {
	t.TrackOutcome(id, TrackedRequestOutcome{Method: method})
}

// TrackOutcome records a request ID as pending and associates it with outcome
// receipt metadata. Nil/null IDs are ignored (notifications don't expect
// responses). If the pending set exceeds maxTrackedRequests, the oldest entry
// is evicted.
func (t *RequestTracker) TrackOutcome(id json.RawMessage, outcome TrackedRequestOutcome) {
	t.trackOutcome(id, outcome)
}

func (t *RequestTracker) trackOutcome(id json.RawMessage, outcome TrackedRequestOutcome) *requestRegistration {
	registration, _, _ := t.registerOutcome(id, outcome)
	return registration
}

type unattributedOutcome struct {
	outcome TrackedRequestOutcome
	reason  string
}

func (t *RequestTracker) registerOutcome(id json.RawMessage, outcome TrackedRequestOutcome) (*requestRegistration, []unattributedOutcome, string) {
	if t == nil {
		return nil, nil, ""
	}
	key := canonicalID(id)
	if key == "" {
		return nil, nil, ""
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var unowned []unattributedOutcome
	retire := func(o TrackedRequestOutcome, reason string) {
		if o.handle != nil {
			unowned = append(unowned, unattributedOutcome{outcome: o, reason: reason})
		}
	}
	if prior, exists := t.pending[key]; exists {
		if prior.outcome.ownsNativeLease || outcome.ownsNativeLease {
			return nil, nil, ""
		}
		// A response to a duplicate outstanding ID has no unique owner.
		if prior.outcome.handle != nil || outcome.handle != nil {
			t.markAmbiguous(key)
			retire(prior.outcome, "ambiguous_request_id")
			retire(outcome, "ambiguous_request_id")
			prior.outcome.Receipt = receipt.EmitOpts{}
			prior.outcome.handle = nil
			t.pending[key] = prior
		}
		return nil, unowned, ""
	}

	_, ambiguous := t.ambiguousIDs[key]
	if outcome.ownsNativeLease && (ambiguous || t.ambiguityLimitReached) {
		return nil, nil, ""
	}

	// Evict oldest if at capacity.
	var evictedKey string
	if len(t.pending) >= maxTrackedRequests {
		oldest := t.order[0]
		evicted := t.pending[oldest].outcome
		_, remembered := t.ambiguousIDs[oldest]
		if evicted.ownsNativeLease || evicted.pinned || (outcome.ownsNativeLease && !remembered && len(t.ambiguousIDs) >= maxTrackedRequests) {
			return nil, nil, ""
		}
		t.markAmbiguous(oldest)
		retire(evicted, "request_tracker_capacity")
		delete(t.pending, oldest)
		evictedKey = oldest
		t.order = t.order[1:]
	}

	if _, ambiguous := t.ambiguousIDs[key]; ambiguous || t.ambiguityLimitReached {
		retire(outcome, "ambiguous_request_id")
		outcome.Receipt = receipt.EmitOpts{}
		outcome.handle = nil
	}
	registration := new(requestRegistration)
	t.pending[key] = trackedRequest{registration: registration, outcome: outcome}
	t.order = append(t.order, key)
	t.seeded = true
	return registration, unowned, evictedKey
}

// markAmbiguous requires t.mu and bounds the ambiguity history.
func (t *RequestTracker) markAmbiguous(key string) {
	if _, known := t.ambiguousIDs[key]; known {
		return
	}
	if len(t.ambiguousIDs) == maxTrackedRequests {
		t.ambiguityLimitReached = true
		return
	}
	if t.ambiguousIDs == nil {
		t.ambiguousIDs = make(map[string]struct{})
	}
	t.ambiguousIDs[key] = struct{}{}
}

// Validate checks whether id was previously tracked, consuming it on
// match (one-shot). Returns true if the ID is valid (was tracked or is
// nil/null). A nil tracker always returns true (feature disabled).
func (t *RequestTracker) Validate(id json.RawMessage) bool {
	_, ok := t.Consume(id)
	return ok
}

// claimRejectedOutcome consumes a paired request when its attributable
// response was denied. A legacy diagnostic retains the pending correlation
// and can be written at most once.
func (t *RequestTracker) claimRejectedOutcome(id json.RawMessage, expected *requestRegistration) (TrackedRequestOutcome, bool) {
	if t == nil {
		return TrackedRequestOutcome{}, false
	}
	key := canonicalID(id)
	if key == "" {
		return TrackedRequestOutcome{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	request, ok := t.pending[key]
	if !ok || request.outcome.readyToCorrelate != nil && !request.outcome.readyToCorrelate.Load() ||
		expected != nil && request.registration != expected || request.rejectionOutcomeClaimed || request.outcome.Receipt.ActionID == "" {
		return TrackedRequestOutcome{}, false
	}
	if request.outcome.handle != nil {
		t.remove(key)
		return request.outcome, true
	}
	request.rejectionOutcomeClaimed = true
	t.pending[key] = request
	// A legacy diagnostic borrows the receipt metadata. The pending request
	// still owns the response reservation until its correlation is consumed.
	request.outcome.ownsNativeLease = false
	return request.outcome, true
}

// takeOwnedOutcome transfers only the registration created for this intent.
func (t *RequestTracker) takeOwnedOutcome(id json.RawMessage, registration *requestRegistration) (TrackedRequestOutcome, bool) {
	if t == nil || registration == nil {
		return TrackedRequestOutcome{}, false
	}
	key := canonicalID(id)
	t.mu.Lock()
	defer t.mu.Unlock()
	req, ok := t.pending[key]
	if !ok || req.registration != registration {
		return TrackedRequestOutcome{}, false
	}
	t.remove(key)
	return req.outcome, true
}

// removeOwnedOutcome discards a registration before an upstream send.
func (t *RequestTracker) removeOwnedOutcome(id json.RawMessage, registration *requestRegistration) {
	if outcome, ok := t.takeOwnedOutcome(id, registration); ok {
		outcome.releaseNativeLease()
	}
}

// nativeAdmission finds the held response lease without consuming the request.
func (t *RequestTracker) nativeAdmission(id json.RawMessage) receipt.EmitOpts {
	if t == nil {
		return receipt.EmitOpts{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pending[canonicalID(id)].outcome.Receipt
}

// Consume checks whether id was previously tracked and returns the associated
// outcome metadata. It consumes matching IDs exactly once.
func (t *RequestTracker) Consume(id json.RawMessage) (TrackedRequestOutcome, bool) {
	if t == nil {
		return TrackedRequestOutcome{}, true
	}
	key := canonicalID(id)
	if key == "" {
		// Nil/null IDs: notifications and server-initiated requests.
		return TrackedRequestOutcome{}, !t.strict
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	request, ok := t.pending[key]
	if !ok || request.outcome.readyToCorrelate != nil && !request.outcome.readyToCorrelate.Load() {
		return TrackedRequestOutcome{}, false
	}
	t.remove(key)
	return request.outcome, true
}

// remove requires the tracker's lock.
func (t *RequestTracker) remove(key string) {
	delete(t.pending, key)
	for i, k := range t.order {
		if k == key {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
	}
}

// Seeded reports whether at least one request ID has been tracked.
// Used by ForwardScanned to skip validation during server initialization
// (before any client request has been sent). A nil tracker returns false.
func (t *RequestTracker) Seeded() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.seeded
}

// HasPending reports whether any tracked request still awaits its response.
// A nil tracker has nothing pending.
func (t *RequestTracker) HasPending() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending) > 0
}

// Strict reports whether response envelopes must carry an exact tracked ID.
func (t *RequestTracker) Strict() bool {
	return t != nil && t.strict
}

// DrainPending returns and removes all pending request IDs. Used when a
// response timeout fires and the proxy needs to emit error responses for
// every unanswered request before shutting down.
func (t *RequestTracker) DrainPending() []json.RawMessage {
	pending := t.DrainPendingOutcomes()
	if pending == nil {
		return nil
	}
	ids := make([]json.RawMessage, 0, len(pending))
	for _, item := range pending {
		ids = append(ids, item.ID)
	}
	return ids
}

// DrainPendingOutcomes returns and removes all pending request IDs with their
// associated outcome metadata.
func (t *RequestTracker) DrainPendingOutcomes() []PendingRequestOutcome {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	pending := make([]PendingRequestOutcome, 0, len(t.order))
	for _, key := range t.order {
		pending = append(pending, PendingRequestOutcome{
			ID:      json.RawMessage(key),
			Outcome: t.pending[key].outcome,
		})
	}
	t.pending = make(map[string]trackedRequest)
	t.order = nil
	return pending
}

// canonicalID normalizes a JSON-RPC ID to a canonical string for map
// lookup. Returns "" for nil, empty, or "null" IDs (notifications).
// The canonical form preserves the raw JSON representation so numeric
// IDs (1) and string IDs ("1") remain distinct.
func canonicalID(id json.RawMessage) string {
	if len(id) == 0 || string(id) == jsonrpc.Null {
		return ""
	}
	return string(id)
}
