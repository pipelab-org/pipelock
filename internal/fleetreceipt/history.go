// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package fleetreceipt

import (
	"fmt"
	"slices"
	"time"
)

// ContinuityUnproven is an assurance limit, not a failed report signature.
const ContinuityUnproven = "cross_session_continuity_unproven"

// History separates retained-window arithmetic from receiver arrival facts.
// Sessions describe all receiver observations in the scoped fleet snapshot;
// Gaps describe only missing sequence ranges between included same-chain batches.
type History struct {
	Continuity       string            `json:"continuity"`
	MultipleSessions bool              `json:"multipleSessions"`
	Sessions         []ObservedChain   `json:"sessions"`
	Gaps             []SequenceGap     `json:"gaps"`
	Retention        RetentionCoverage `json:"retention"`
}

type ObservedChain struct {
	InstanceID       string        `json:"instanceId"`
	Chain            ChainIdentity `json:"chain"`
	FirstReceived    string        `json:"firstReceived"`
	LastReceived     string        `json:"lastReceived"`
	SeqStart         uint64        `json:"seqStart"`
	SeqEnd           uint64        `json:"seqEnd"`
	RetainedBackfill bool          `json:"retainedBackfill"`
}

type SequenceGap struct {
	InstanceID string        `json:"instanceId"`
	Chain      ChainIdentity `json:"chain"`
	SeqStart   uint64        `json:"seqStart"`
	SeqEnd     uint64        `json:"seqEnd"`
}

type RetentionCoverage struct {
	ObservationsSince string `json:"observationsSince,omitempty"`
	HistoryUnknown    bool   `json:"historyUnknown"`
	PrunedBefore      string `json:"prunedBefore,omitempty"`
}

func (h History) validate(batches []SourceBatch) error {
	gaps, multiple := HistoryFacts(batches, h.Sessions)
	if h.MultipleSessions != multiple || !slices.Equal(h.Gaps, gaps) {
		return fmt.Errorf("%w: history facts disagree with source ranges and observations", ErrInvalidPredicate)
	}
	if h.Continuity != ContinuityUnproven {
		return fmt.Errorf("%w: unsupported history continuity", ErrInvalidPredicate)
	}
	if h.Sessions == nil || h.Gaps == nil {
		return fmt.Errorf("%w: history sessions and gaps must be arrays", ErrInvalidPredicate)
	}
	for _, s := range h.Sessions {
		if s.InstanceID == "" || s.SeqEnd < s.SeqStart {
			return fmt.Errorf("%w: invalid observed chain", ErrInvalidPredicate)
		}
		if err := s.Chain.Validate(); err != nil {
			return err
		}
		a, err := parseTime("history.firstReceived", s.FirstReceived)
		if err != nil {
			return err
		}
		b, err := parseTime("history.lastReceived", s.LastReceived)
		if err != nil {
			return err
		}
		if a.After(b) {
			return fmt.Errorf("%w: observation arrival range", ErrInvalidPredicate)
		}
	}
	for _, g := range h.Gaps {
		if g.InstanceID == "" || g.SeqEnd < g.SeqStart {
			return fmt.Errorf("%w: invalid history gap", ErrInvalidPredicate)
		}
		if err := g.Chain.Validate(); err != nil {
			return err
		}
	}
	for name, value := range map[string]string{"observationsSince": h.Retention.ObservationsSince, "prunedBefore": h.Retention.PrunedBefore} {
		if value != "" {
			if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
				return fmt.Errorf("%w: history %s: %w", ErrInvalidPredicate, name, err)
			}
		}
	}
	if h.Retention.ObservationsSince == "" && !h.Retention.HistoryUnknown {
		return fmt.Errorf("%w: missing observation coverage must remain unknown", ErrInvalidPredicate)
	}
	return nil
}

// HistoryFacts derives only visible sequence gaps and the presence of multiple
// sessions. It does not order independent sessions or claim missing outer ranges.
func HistoryFacts(batches []SourceBatch, observations []ObservedChain) ([]SequenceGap, bool) {
	gaps := []SequenceGap{}
	sessions := map[string]map[string]bool{}
	multiple := false
	remember := func(instance, session string) {
		if sessions[instance] == nil {
			sessions[instance] = map[string]bool{}
		}
		sessions[instance][session] = true
		if len(sessions[instance]) > 1 {
			multiple = true
		}
	}
	for _, o := range observations {
		remember(o.InstanceID, o.Chain.SessionID)
	}
	type key struct {
		instance string
		chain    ChainIdentity
	}
	last := map[key]uint64{}
	for _, b := range batches {
		if b.Chain == nil {
			continue
		}
		remember(b.InstanceID, b.Chain.SessionID)
		k := key{b.InstanceID, *b.Chain}
		if end, ok := last[k]; ok && end != ^uint64(0) && b.SeqStart > end+1 {
			gaps = append(gaps, SequenceGap{InstanceID: b.InstanceID, Chain: *b.Chain, SeqStart: end + 1, SeqEnd: b.SeqStart - 1})
		}
		last[k] = b.SeqEnd
	}
	return gaps, multiple
}
