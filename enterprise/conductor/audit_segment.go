//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// ValidateAuditSegment checks the existing segment-local sequence, endpoint and
// namespace contract. The first entry may follow an earlier segment, rather
// than genesis. This does not verify entry hashes or authenticate a signer.
func ValidateAuditSegment(chain EvidenceChain, entries []recorder.Entry) error {
	if len(entries) == 0 {
		return errors.New("empty payload")
	}
	if entries[0].Sequence != chain.SeqStart || entries[len(entries)-1].Sequence != chain.SeqEnd {
		return errors.New("sequence range mismatch")
	}
	if entries[0].Hash != chain.SegmentHeadHash || entries[len(entries)-1].Hash != chain.SegmentTailHash {
		return errors.New("chain head/tail mismatch")
	}
	for _, entry := range entries {
		if !recorder.IsAcceptedEntryVersion(entry.Version) {
			return fmt.Errorf("seq %d unsupported recorder entry version %d", entry.Sequence, entry.Version)
		}
		if err := recorder.ValidateEntrySchema(entry); err != nil {
			return fmt.Errorf("seq %d invalid recorder entry: %w", entry.Sequence, err)
		}
		if entry.Version != chain.EntryVersion ||
			(recorder.EntryVersionHasNamespace(entry.Version) && entry.SessionID != chain.SessionID) ||
			entry.ChainKind != chain.ChainKind || entry.WriterInstanceID != chain.WriterInstanceID {
			return fmt.Errorf("seq %d chain namespace mismatch", entry.Sequence)
		}
	}
	for i := 1; i < len(entries); i++ {
		entry := entries[i]
		prev := entries[i-1]
		if entry.Sequence <= prev.Sequence || entry.Sequence != prev.Sequence+1 {
			return fmt.Errorf("seq gap at %d", entry.Sequence)
		}
		if entry.PrevHash != prev.Hash {
			return fmt.Errorf("seq %d chain link mismatch", entry.Sequence)
		}
	}
	return nil
}

// LegacyPayloadSession returns a validated v2 payload session, or an empty
// string when the payload cannot establish one. Callers MUST authenticate the
// envelope with the enrolled audit signer before using this identity. The
// signed payload digest binds the session; embedded recorder keys do not.
// Historical admitted rows need no new timestamp-skew check or resigning.
// Unknown identity never grants an exemption from the legacy fork comparator.
func (a AuditBatchEnvelope) LegacyPayloadSession(ctx context.Context, payload []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if a.Chain.EntryVersion != 2 || a.Chain.SessionID != "" {
		return "", nil
	}
	identity, err := a.PayloadNamespace(ctx, payload)
	return identity.SessionID, err
}

// AuditNamespace is derived from a validated payload, not an operator label.
// A zero value means unresolved identity and must never grant fork exemptions.
type AuditNamespace struct {
	EntryVersion     int
	SessionID        string
	ChainKind        string
	WriterInstanceID string
}

// PayloadNamespace checks both supported hash projections after the caller has
// authenticated the envelope. Historical evidence does not need a fresh skew check.
func (a AuditBatchEnvelope) PayloadNamespace(ctx context.Context, payload []byte) (AuditNamespace, error) {
	if err := ctx.Err(); err != nil {
		return AuditNamespace{}, err
	}
	if len(payload) > MaxAuditPayloadBytes {
		return AuditNamespace{}, nil
	}
	if a.Validate() != nil || a.ValidatePayload(payload) != nil {
		return AuditNamespace{}, nil
	}
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(payload))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return AuditNamespace{}, ctxErr
	}
	if err != nil || uint64(len(entries)) != a.EventCount || ValidateAuditSegment(a.Chain, entries) != nil {
		return AuditNamespace{}, nil
	}
	session := entries[0].SessionID
	if session == "" {
		return AuditNamespace{}, nil
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return AuditNamespace{}, err
		}
		if entry.SessionID != session || recorder.ComputeHash(entry) != entry.Hash {
			return AuditNamespace{}, nil
		}
	}
	// Producer segments end at their signed checkpoint. Bind its metadata too;
	// checking the signature against an embedded, untrusted key adds no authority.
	last := entries[len(entries)-1]
	if last.Type != "checkpoint" || last.Sequence != a.Chain.CheckpointSeq || last.Hash != a.Chain.CheckpointHash {
		return AuditNamespace{}, nil
	}
	var checkpoint recorder.CheckpointDetail
	if json.Unmarshal(last.RawDetail, &checkpoint) != nil || checkpoint.Signature == "" ||
		SignaturePrefixEd25519+strings.TrimPrefix(checkpoint.Signature, SignaturePrefixEd25519) != a.Chain.CheckpointSignature {
		return AuditNamespace{}, nil
	}
	return AuditNamespace{EntryVersion: entries[0].Version, SessionID: session, ChainKind: entries[0].ChainKind, WriterInstanceID: entries[0].WriterInstanceID}, nil
}
