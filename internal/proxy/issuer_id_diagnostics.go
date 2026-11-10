// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import "net/url"

// issuerIDHistoryBlock records the first reason complete send history was
// lost. The existing bounded tombstone map holds it; it grants no allowance.
type issuerIDHistoryBlock uint8

const (
	issuerHistoryComplete issuerIDHistoryBlock = iota
	issuerHistoryUnknown
	issuerHistoryUnreadBody
	issuerHistoryRequestLimit
	issuerHistoryDestinationLimit
	issuerHistoryTotalLimit
	issuerHistoryStream
	issuerHistoryUnknownDestination
)

func (reason issuerIDHistoryBlock) String() string {
	switch reason {
	case issuerHistoryUnreadBody:
		return "destination_learning_frozen_unread_body"
	case issuerHistoryRequestLimit:
		return "destination_learning_frozen_request_limit"
	case issuerHistoryDestinationLimit:
		return "destination_learning_frozen_destination_limit"
	case issuerHistoryTotalLimit:
		return "destination_learning_frozen_total_limit"
	case issuerHistoryStream:
		return "destination_learning_frozen_stream"
	default:
		return "destination_learning_frozen_incomplete"
	}
}

// issuerIDBlockReason explains the request's actual evidence prerequisites and
// history state to the operator audit log. It must never create history, mint
// an allowance, inspect matched bytes or disclose state to the client.
func (ic *InterceptContext) issuerIDBlockReason(target *url.URL) string {
	if ic == nil || ic.Proxy == nil {
		return "store_unavailable"
	}
	if !ic.ActorAuth.TrustedForIdentity() {
		return "untrusted_actor"
	}
	if !issuerCookieEnabled(ic.Config) {
		return "disabled"
	}
	runtime := ic.Proxy.issuerCookieRuntime.Load()
	if runtime == nil || runtime.query == nil {
		return "store_unavailable"
	}
	if (ic.IssuerRuntime != nil && ic.IssuerRuntime != runtime) ||
		(ic.IssuerRuntime == nil && runtime.cfg != ic.Config) {
		return "stale_runtime"
	}
	store := runtime.query
	session := sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.disabled {
		return "store_unavailable"
	}
	if issuerSentHost(target) == "" {
		return "destination_unknown"
	}
	caller := store.history[session]
	if caller != nil && caller.block != issuerHistoryComplete {
		return "caller_learning_frozen"
	}
	bucket := store.idDestinationLocked(session, target)
	if bucket == nil {
		// The caller limit matters only to a caller that has not been admitted.
		if store.idAdmissionClosed || store.idDestinations >= issuerUnreadableMaxSessions || (caller == nil && len(store.history) >= issuerUnreadableMaxSessions) {
			return "destination_history_capacity"
		}
		return "destination_history_missing"
	}
	if bucket.block != issuerHistoryComplete {
		return bucket.block.String()
	}
	// History alone cannot tell an ID that was never delivered from one refused
	// as a caller-first reflection, an evicted one, or a segment that is not an
	// ID at all. Do not invent that attribution.
	return "no_allowance"
}
