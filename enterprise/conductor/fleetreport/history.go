//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package fleetreport

import (
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
)

func reportHistory(batches []fleetreceipt.SourceBatch, snapshot controlplane.AuditEvidenceSnapshot) *fleetreceipt.History {
	h := &fleetreceipt.History{Continuity: fleetreceipt.ContinuityUnproven, Sessions: []fleetreceipt.ObservedChain{}, Gaps: []fleetreceipt.SequenceGap{}, Retention: fleetreceipt.RetentionCoverage{ObservationsSince: snapshot.Coverage.ObservationsSince, HistoryUnknown: snapshot.Coverage.HistoryUnknown, PrunedBefore: snapshot.Coverage.PrunedBefore}}
	for _, o := range snapshot.Observations {
		h.Sessions = append(h.Sessions, fleetreceipt.ObservedChain{InstanceID: o.InstanceID, Chain: fleetreceipt.ChainIdentity{EntryVersion: o.EntryVersion, SessionID: o.SessionID, ChainKind: o.ChainKind, WriterInstanceID: o.WriterInstanceID}, FirstReceived: o.FirstReceived, LastReceived: o.LastReceived, SeqStart: o.SeqStart, SeqEnd: o.SeqEnd, RetainedBackfill: o.RetainedBackfill})
	}
	h.Gaps, h.MultipleSessions = fleetreceipt.HistoryFacts(batches, h.Sessions)
	return h
}
