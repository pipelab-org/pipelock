// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

// issuerIDHistoryBlock records the first reason complete send history was
// lost. The existing bounded tombstone map holds it; it grants no allowance.
type issuerIDHistoryBlock uint8

const (
	issuerHistoryComplete issuerIDHistoryBlock = iota
	issuerHistoryUnknown
	issuerHistoryUnreadBody
	issuerHistoryRequestLimit
	issuerHistorySessionLimit
	issuerHistoryTotalLimit
	issuerHistoryStream
)

func (reason issuerIDHistoryBlock) String() string {
	switch reason {
	case issuerHistoryUnreadBody:
		return "history_unread_body"
	case issuerHistoryRequestLimit:
		return "history_request_limit"
	case issuerHistorySessionLimit:
		return "history_session_limit"
	case issuerHistoryTotalLimit:
		return "history_total_limit"
	case issuerHistoryStream:
		return "history_stream"
	default:
		return "history_incomplete"
	}
}

// issuerIDBlockReason explains the request's actual evidence prerequisites and
// history state to the operator audit log. It must never create history, mint
// an allowance, inspect matched bytes or disclose state to the client.
func (ic *InterceptContext) issuerIDBlockReason() string {
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
	if reason := store.sentUnreadable[session]; reason != issuerHistoryComplete {
		return reason.String()
	}
	if store.sent[session] == nil {
		if len(store.sent) >= issuerUnreadableMaxSessions {
			return "history_capacity"
		}
		return "history_missing"
	}
	// History alone cannot tell an ID that was never delivered from one refused
	// as a caller-first reflection, an evicted one, or a segment that is not an
	// ID at all. Do not invent that attribution.
	return "no_allowance"
}
