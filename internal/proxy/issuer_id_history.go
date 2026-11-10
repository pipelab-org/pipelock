// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/url"

	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

// All history and allowance state is protected by the shared issuerIDLedger.mu.
// Destination keys are keyed digests; no hostname or sent value is retained.
type issuerIDCaller struct {
	block        issuerIDHistoryBlock
	destinations map[[32]byte]*issuerIDDestination
}

type issuerIDDestination struct {
	block issuerIDHistoryBlock
	sent  map[[32]byte]issuerSentProvenance
}

// issuerIDEntry is one retained proof. While its destination can still learn,
// it is linked into its caller's recency ring. Once found frozen it is unlinked
// (pinned) for good, because freezes are permanent and pinned proofs are never
// victims.
type issuerIDEntry struct {
	digest      [32]byte
	destination *issuerIDDestination
	prev, next  *issuerIDEntry
}

func (e *issuerIDEntry) replaceable() bool {
	return e.destination != nil && e.destination.block == issuerHistoryComplete
}

// issuerIDCache holds one caller's proofs. order is the sentinel of a ring of
// replaceable entries, most recent first, so touch and eviction cost amortized
// O(1) under the shared ledger lock instead of a scan of every entry.
type issuerIDCache struct {
	entries map[[32]byte]*issuerIDEntry
	order   issuerIDEntry
}

func newIssuerIDCache() *issuerIDCache {
	c := &issuerIDCache{entries: make(map[[32]byte]*issuerIDEntry)}
	c.order.prev, c.order.next = &c.order, &c.order
	return c
}

func (c *issuerIDCache) unlink(e *issuerIDEntry) {
	if e.next == nil {
		return
	}
	e.prev.next, e.next.prev = e.next, e.prev
	e.prev, e.next = nil, nil
}

// touch marks e as the most recently delivered or used. It changes retention
// order only, never which IDs are allowed; pinned entries stay unlinked.
func (c *issuerIDCache) touch(e *issuerIDEntry) {
	c.unlink(e)
	if !e.replaceable() {
		return
	}
	e.prev, e.next = &c.order, c.order.next
	c.order.next.prev = e
	c.order.next = e
}

// leastRecentReplaceable returns the least recently delivered or used entry
// whose destination can still learn. Entries at the old end whose destination
// has since frozen are pinned on the way, each at most once.
func (c *issuerIDCache) leastRecentReplaceable() *issuerIDEntry {
	for e := c.order.prev; e != &c.order; e = c.order.prev {
		if e.replaceable() {
			return e
		}
		c.unlink(e)
	}
	return nil
}

func (c *issuerIDCache) remove(e *issuerIDEntry) {
	c.unlink(e)
	delete(c.entries, e.digest)
}

func (s *issuerQueryStore) closeIDAdmissionLocked() {
	s.idAdmissionClosed = true
	if !s.idCapacityReported && s.observeIDBlock != nil {
		s.observeIDBlock(metrics.IssuerIDBlockCapacity, true)
	}
	s.idCapacityReported = true
}

func (s *issuerQueryStore) admitIDCallerLocked(session string) *issuerIDCaller {
	if caller := s.history[session]; caller != nil {
		return caller
	}
	if s.idAdmissionClosed || len(s.history) >= issuerUnreadableMaxSessions {
		s.closeIDAdmissionLocked()
		return nil
	}
	caller := &issuerIDCaller{destinations: make(map[[32]byte]*issuerIDDestination)}
	s.history[session] = caller
	return caller
}

func (s *issuerQueryStore) idDestinationLocked(session string, target *url.URL) *issuerIDDestination {
	host := issuerSentHost(target)
	if host == "" {
		return nil
	}
	return s.idDestinationByKeyLocked(session, s.idDestinationKey(host))
}

// idDestinationKey costs an HMAC; callers compute it before taking s.mu.
func (s *issuerQueryStore) idDestinationKey(host string) [32]byte {
	return s.digestFields("id_destination", host)
}

func (s *issuerQueryStore) idDestinationByKeyLocked(session string, key [32]byte) *issuerIDDestination {
	caller := s.history[session]
	if caller == nil {
		return nil
	}
	return caller.destinations[key]
}

func (s *issuerQueryStore) admitIDDestinationLocked(session string, target *url.URL) *issuerIDDestination {
	host := issuerSentHost(target)
	if host == "" {
		s.freezeIDCallerLocked(session)
		return nil
	}
	caller := s.admitIDCallerLocked(session)
	if caller == nil || caller.block != issuerHistoryComplete {
		return nil
	}
	key := s.digestFields("id_destination", host)
	if bucket := caller.destinations[key]; bucket != nil {
		return bucket
	}
	if s.idAdmissionClosed || s.idDestinations >= issuerUnreadableMaxSessions {
		s.closeIDAdmissionLocked()
		return nil
	}
	bucket := &issuerIDDestination{sent: make(map[[32]byte]issuerSentProvenance)}
	caller.destinations[key] = bucket
	s.idDestinations++
	return bucket
}

func (s *issuerQueryStore) freezeIDDestinationLocked(bucket *issuerIDDestination, reason issuerIDHistoryBlock) {
	if bucket.block != issuerHistoryComplete {
		return
	}
	if reason == issuerHistoryComplete {
		reason = issuerHistoryUnknown
	}
	bucket.block = reason
	// A permanent deny-to-learn tombstone subsumes the entire token set.
	s.sentEntries -= len(bucket.sent)
	bucket.sent = nil
	s.observeIDFreezeLocked(metrics.IssuerIDBlockDestination)
}

func (s *issuerQueryStore) freezeIDCallerLocked(session string) {
	caller := s.admitIDCallerLocked(session)
	if caller == nil || caller.block != issuerHistoryComplete {
		return
	}
	caller.block = issuerHistoryUnknownDestination
	for _, bucket := range caller.destinations {
		s.sentEntries -= len(bucket.sent)
		bucket.sent = nil
	}
	s.observeIDFreezeLocked(metrics.IssuerIDBlockSession)
}

func (s *issuerQueryStore) observeIDFreezeLocked(scope string) {
	if s.observeIDBlock != nil {
		s.observeIDBlock(scope, !s.idBlockReported)
	}
	s.idBlockReported = true
}

// Missing history never means empty history. Neither responses nor lookups
// can create it, and a freeze or refused admission is never undone.
func (s *issuerQueryStore) mintBlockedLocked(session string, target *url.URL) bool {
	host := issuerSentHost(target)
	return host == "" || s.learningDestinationLocked(session, s.idDestinationKey(host)) == nil
}

// learningDestinationLocked returns the destination only while both the
// caller and the destination can still learn new IDs.
func (s *issuerQueryStore) learningDestinationLocked(session string, key [32]byte) *issuerIDDestination {
	caller := s.history[session]
	if caller == nil || caller.block != issuerHistoryComplete {
		return nil
	}
	bucket := caller.destinations[key]
	if bucket == nil || bucket.block != issuerHistoryComplete {
		return nil
	}
	return bucket
}
