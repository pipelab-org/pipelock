//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package fleetreport mints Fleet Receipt Reports from locally accepted
// Conductor audit-batch evidence.
package fleetreport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	defaultCompletenessBasis    = "included_signed_audit_batches"
	defaultCompletenessClaim    = "fraction of observed fleet action records in included signed audit batches that were mediated by Pipelock"
	defaultCompletenessNonClaim = "does not prove no bypass occurred outside Pipelock, outside enrolled followers, or outside the report window"
)

var (
	ErrNoEvidence          = errors.New("fleet report: no audit-batch evidence matched the query")
	ErrNoActionReceipts    = errors.New("fleet report: no action_receipt records found in matched evidence")
	ErrNonTerminatingRatio = errors.New("fleet report: mediated fraction is not representable as an exact decimal")
	// ErrV1MultipleRuns refuses a v1 window that holds more than one recorder
	// chain for a follower. V1 has no field to state that continuity between
	// runs is unproven, so a signed v1 report would present them as one history.
	ErrV1MultipleRuns = errors.New("fleet report: v1 cannot represent more than one recorder run per follower")
	newReportUUID     = uuid.NewV7
)

type EvidenceSource interface {
	ListAuditBatchEvidence(context.Context, controlplane.AuditEvidenceQuery) ([]controlplane.AuditBatchEvidence, error)
}

type Options struct {
	// ReportVersion defaults to v2; v1 retains per-follower overlap refusal and
	// refuses more than one recorder run per follower.
	ReportVersion    int
	OrgID            string
	FleetID          string
	ReportID         string
	WindowStart      time.Time
	WindowEnd        time.Time
	ConductorID      string
	ConductorVersion string
	SignerKeyID      string
	Signer           ed25519.PrivateKey
	AuditKeys        controlplane.AuditKeyResolver
	Limit            int
	GeneratedAt      time.Time
}

type Result struct {
	Envelope  fleetreceipt.Envelope
	Statement fleetreceipt.Statement
}

func Build(ctx context.Context, source EvidenceSource, opts Options) (Result, error) {
	if source == nil {
		return Result{}, errors.New("fleet report: evidence source is required")
	}
	if opts.ReportVersion == 0 {
		opts.ReportVersion = fleetreceipt.SchemaVersionV2
	}
	if err := validateOptions(opts); err != nil {
		return Result{}, err
	}
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}
	query := controlplane.AuditEvidenceQuery{
		OrgID:        opts.OrgID,
		FleetID:      opts.FleetID,
		ReceivedFrom: opts.WindowStart,
		ReceivedTo:   opts.WindowEnd,
		Limit:        opts.Limit,
	}
	var evidence []controlplane.AuditBatchEvidence
	var snapshot controlplane.AuditEvidenceSnapshot
	var err error
	if snapshots, ok := source.(interface {
		AuditEvidenceSnapshot(context.Context, controlplane.AuditEvidenceQuery) (controlplane.AuditEvidenceSnapshot, error)
	}); ok {
		snapshot, err = snapshots.AuditEvidenceSnapshot(ctx, query)
		evidence = snapshot.Batches
	} else {
		evidence, err = source.ListAuditBatchEvidence(ctx, query)
		snapshot.Coverage.HistoryUnknown = true
	}
	if err != nil {
		return Result{}, err
	}
	if len(evidence) == 0 {
		return Result{}, ErrNoEvidence
	}
	agg := newAggregator()
	v1Runs := v1RunSet{}
	var sourceBatches []fleetreceipt.SourceBatch
	for _, ev := range evidence {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if err := validateEvidence(opts, ev); err != nil {
			return Result{}, err
		}
		identity := controlplane.FollowerIdentity{OrgID: ev.Envelope.OrgID, FleetID: ev.Envelope.FleetID, InstanceID: ev.Envelope.InstanceID}
		var auditKey conductorcore.SignatureKey
		if opts.AuditKeys != nil {
			if err := ev.Envelope.VerifySignaturesAt(ev.Summary.ReceivedAt, func(signerKeyID string) (conductorcore.SignatureKey, error) {
				key, err := opts.AuditKeys(identity, signerKeyID)
				if err == nil {
					auditKey = key
				}
				return key, err
			}); err != nil {
				return Result{}, fmt.Errorf("fleet report: verify audit batch %s: %w", ev.Envelope.BatchID, err)
			}
		}
		entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(ev.Payload))
		if err != nil {
			return Result{}, fmt.Errorf("fleet report: parse audit payload %s: %w", ev.Envelope.BatchID, err)
		}
		if uint64(len(entries)) != ev.Envelope.EventCount {
			return Result{}, fmt.Errorf("fleet report: audit batch %s event count=%d want %d", ev.Envelope.BatchID, len(entries), ev.Envelope.EventCount)
		}
		if err := verifySegment(ev.Envelope.BatchID, ev.Envelope.Chain, entries); err != nil {
			return Result{}, err
		}
		if err := agg.addBatch(ev, entries, auditKey); err != nil {
			return Result{}, err
		}
		if opts.ReportVersion == fleetreceipt.SchemaVersionV1 {
			if err := v1Runs.add(ev.Envelope.InstanceID, entries); err != nil {
				return Result{}, err
			}
		}
		batch := sourceBatch(ev)
		if opts.ReportVersion == fleetreceipt.SchemaVersionV2 {
			if len(auditKey.PublicKey) != ed25519.PublicKeySize {
				return Result{}, fmt.Errorf("fleet report: no enrolled audit key available for namespace in batch %s", ev.Envelope.BatchID)
			}
			identity, err := deriveChainIdentity(ctx, ev.Envelope, entries)
			if err != nil {
				return Result{}, fmt.Errorf("fleet report: batch %s namespace: %w", ev.Envelope.BatchID, err)
			}
			batch.Chain = &identity
		}
		sourceBatches = append(sourceBatches, batch)
	}
	if opts.ReportVersion == fleetreceipt.SchemaVersionV2 {
		slices.SortFunc(sourceBatches, fleetreceipt.CompareSourceBatches)
	}
	subjects := make([]fleetreceipt.Subject, 0, len(sourceBatches))
	for _, batch := range sourceBatches {
		subjects = append(subjects, fleetreceipt.Subject{Name: sourceBatchSubjectName(batch), Digest: fleetreceipt.Digest{SHA256: batch.EnvelopeHash}})
	}
	predicateType := fleetreceipt.PredicateType
	if opts.ReportVersion == fleetreceipt.SchemaVersionV2 {
		predicateType = fleetreceipt.PredicateTypeV2
	}
	if agg.totalActions == 0 {
		return Result{}, ErrNoActionReceipts
	}
	fraction, err := exactDecimalRatio(agg.mediatedActions, agg.totalActions)
	if err != nil {
		return Result{}, err
	}
	id, err := reportID(opts.ReportID)
	if err != nil {
		return Result{}, err
	}
	statement := fleetreceipt.Statement{
		Type:          fleetreceipt.StatementType,
		Subject:       subjects,
		PredicateType: predicateType,
		Predicate: fleetreceipt.Predicate{
			SchemaVersion:     opts.ReportVersion,
			ReportID:          id,
			GeneratedAt:       opts.GeneratedAt.UTC().Format(time.RFC3339),
			OrgID:             opts.OrgID,
			FleetID:           opts.FleetID,
			ReportWindow:      fleetreceipt.TimeWindow{Start: opts.WindowStart.UTC().Format(time.RFC3339), End: opts.WindowEnd.UTC().Format(time.RFC3339)},
			VerificationLevel: fleetreceipt.VerificationLevelL1,
			Conductor:         fleetreceipt.Conductor{ID: opts.ConductorID, Version: opts.ConductorVersion},
			SourceBatches:     sourceBatches,
			Summary: fleetreceipt.Summary{
				TotalActions: agg.totalActions,
				ByFollower:   agg.byFollower,
				ByTransport:  agg.byTransport,
				ByActionType: agg.byActionType,
				ByVerdict:    agg.byVerdict,
				ByLayer:      agg.byLayer,
				BySeverity:   agg.bySeverity,
			},
			Completeness: fleetreceipt.Completeness{
				ObservedActions:        agg.totalActions,
				DroppedObservedActions: agg.droppedActions,
				MediatedActions:        agg.mediatedActions,
				MediatedFraction:       fraction,
				Basis:                  defaultCompletenessBasis,
				Claim:                  defaultCompletenessClaim,
				NonClaim:               defaultCompletenessNonClaim,
			},
			Limits: []string{
				"L1 verifies the signed report, source-batch anchors, ordering, summary arithmetic, and completeness arithmetic.",
				"L1 does not replay raw audit-batch payloads during offline verification.",
				"Actions outside included signed audit batches are not claimed by this report.",
			},
		},
	}
	if opts.ReportVersion == fleetreceipt.SchemaVersionV2 {
		statement.Predicate.History = reportHistory(sourceBatches, snapshot)
		statement.Predicate.Limits = append(statement.Predicate.Limits,
			"Cross-session continuity unproven: distinct sessions are signer-attested histories, not authenticated restarts or predecessors.",
			"Session observations describe the receiver snapshot; first/last arrival do not establish source order. Backfilled observations begin at earliest retained evidence.",
			"Conflict comparison covers retained batch history only. Pruned payloads and evidence before observation coverage cannot establish complete history.")
	}
	envelope, err := fleetreceipt.SignStatement(statement, opts.SignerKeyID, opts.Signer)
	if err != nil {
		return Result{}, err
	}
	return Result{Envelope: envelope, Statement: statement}, nil
}

func validateOptions(opts Options) error {
	if opts.ReportVersion != 0 && opts.ReportVersion != fleetreceipt.SchemaVersionV1 && opts.ReportVersion != fleetreceipt.SchemaVersionV2 {
		return errors.New("fleet report: unsupported report version; use 1 or 2")
	}
	if strings.TrimSpace(opts.OrgID) == "" {
		return errors.New("fleet report: org id is required")
	}
	if strings.TrimSpace(opts.FleetID) == "" {
		return errors.New("fleet report: fleet id is required")
	}
	if strings.TrimSpace(opts.ConductorID) == "" {
		return errors.New("fleet report: conductor id is required")
	}
	if opts.WindowStart.IsZero() || opts.WindowEnd.IsZero() || !opts.WindowEnd.After(opts.WindowStart) {
		return errors.New("fleet report: invalid report window")
	}
	if len(opts.Signer) != ed25519.PrivateKeySize {
		return fmt.Errorf("fleet report: signer private key length=%d want %d", len(opts.Signer), ed25519.PrivateKeySize)
	}
	if opts.Limit < 0 {
		return errors.New("fleet report: limit must be non-negative")
	}
	return nil
}

func reportID(value string) (string, error) {
	if strings.TrimSpace(value) != "" {
		return value, nil
	}
	id, err := newReportUUID()
	if err != nil {
		return "", fmt.Errorf("fleet report: generate report id: %w", err)
	}
	return id.String(), nil
}

func validateEvidence(opts Options, ev controlplane.AuditBatchEvidence) error {
	if ev.Envelope.OrgID != opts.OrgID || ev.Envelope.FleetID != opts.FleetID {
		return fmt.Errorf("fleet report: audit batch %s belongs to %s/%s, want %s/%s", ev.Envelope.BatchID, ev.Envelope.OrgID, ev.Envelope.FleetID, opts.OrgID, opts.FleetID)
	}
	if err := ev.Envelope.ValidatePayload(ev.Payload); err != nil {
		return fmt.Errorf("fleet report: audit batch %s payload: %w", ev.Envelope.BatchID, err)
	}
	hash, err := ev.Envelope.CanonicalHash()
	if err != nil {
		return fmt.Errorf("fleet report: audit batch %s envelope hash: %w", ev.Envelope.BatchID, err)
	}
	if hash != ev.Summary.EnvelopeHash {
		return fmt.Errorf("fleet report: audit batch %s envelope hash mismatch", ev.Envelope.BatchID)
	}
	return nil
}

type aggregator struct {
	totalActions    uint64
	mediatedActions uint64
	droppedActions  uint64
	byFollower      map[string]uint64
	byTransport     map[string]uint64
	byActionType    map[string]uint64
	byVerdict       map[string]uint64
	byLayer         map[string]uint64
	bySeverity      map[string]uint64
}

func newAggregator() *aggregator {
	return &aggregator{
		byFollower:   make(map[string]uint64),
		byTransport:  make(map[string]uint64),
		byActionType: make(map[string]uint64),
		byVerdict:    make(map[string]uint64),
		byLayer:      make(map[string]uint64),
		bySeverity:   make(map[string]uint64),
	}
}

func (a *aggregator) addBatch(ev controlplane.AuditBatchEvidence, entries []recorder.Entry, auditKey conductorcore.SignatureKey) error {
	if ev.Envelope.Dropped.Count > math.MaxUint64-a.droppedActions {
		return fmt.Errorf("fleet report: dropped action count overflow")
	}
	a.droppedActions += ev.Envelope.Dropped.Count
	for _, entry := range entries {
		if entry.Type != "action_receipt" {
			continue
		}
		rcpt, err := decodeReceiptDetail(entry.Detail)
		if err != nil {
			return fmt.Errorf("fleet report: parse action receipt in batch %s seq %d: %w", ev.Envelope.BatchID, entry.Sequence, err)
		}
		if len(auditKey.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("fleet report: no enrolled audit key available for action receipt in batch %s seq %d", ev.Envelope.BatchID, entry.Sequence)
		}
		if err := receipt.VerifyWithKey(rcpt, hexPublicKey(auditKey.PublicKey)); err != nil {
			return fmt.Errorf("fleet report: verify action receipt in batch %s seq %d: %w", ev.Envelope.BatchID, entry.Sequence, err)
		}
		a.addReceipt(ev.Envelope.InstanceID, rcpt.ActionRecord)
	}
	return nil
}

func hexPublicKey(pub ed25519.PublicKey) string {
	return fmt.Sprintf("%x", []byte(pub))
}

func decodeReceiptDetail(detail any) (receipt.Receipt, error) {
	raw, err := json.Marshal(detail)
	if err != nil {
		return receipt.Receipt{}, err
	}
	return receipt.Unmarshal(raw)
}

func verifySegment(batchID string, chain conductorcore.EvidenceChain, entries []recorder.Entry) error {
	if err := conductorcore.ValidateAuditSegment(chain, entries); err != nil {
		return fmt.Errorf("fleet report: audit batch %s %w", batchID, err)
	}
	return nil
}

// deriveChainIdentity joins verifySegment and the recorder's hash projection.
// Call only after authenticating the envelope and checking its payload digest.
// v1Run is the recorder chain a v1 report attributes to one follower, keyed by
// the same namespace fields the receivers compare. Entries without a session
// share one value, so legacy recorders keep v1's original overlap checks.
type v1Run struct {
	entryVersion int
	sessionID    string
	chainKind    string
	writerID     string
}

type v1RunSet map[string]v1Run

// add runs after verifySegment, which rejects empty segments and mixed v3
// namespaces. Legacy segments need a separate session consistency check.
func (s v1RunSet) add(instanceID string, entries []recorder.Entry) error {
	first := entries[0]
	for _, entry := range entries[1:] {
		if entry.SessionID != first.SessionID {
			return fmt.Errorf("%w: follower %s has mixed recorder sessions within an audit batch; neither report version can represent this batch, so narrow --from and --to to exclude it", ErrV1MultipleRuns, instanceID)
		}
	}
	run := v1Run{entryVersion: first.Version, sessionID: first.SessionID, chainKind: first.ChainKind, writerID: first.WriterInstanceID}
	if prev, ok := s[instanceID]; ok && prev != run {
		// V2 can't group a session-less batch by run either, so only a
		// narrower window resolves a mix that includes one.
		if prev.sessionID == "" || run.sessionID == "" {
			return fmt.Errorf("%w: follower %s has session-less and session-bearing audit batches in this window; neither report version can group a session-less batch by recorder run, so narrow --from and --to to one recorder run", ErrV1MultipleRuns, instanceID)
		}
		return fmt.Errorf("%w: follower %s has audit batches from more than one recorder run in this window; use --report-version 2, which records each run separately", ErrV1MultipleRuns, instanceID)
	}
	s[instanceID] = run
	return nil
}

func deriveChainIdentity(ctx context.Context, env conductorcore.AuditBatchEnvelope, entries []recorder.Entry) (fleetreceipt.ChainIdentity, error) {
	first := entries[0] // verifySegment has already rejected empty payloads.
	identity := fleetreceipt.ChainIdentity{EntryVersion: first.Version, SessionID: first.SessionID, ChainKind: first.ChainKind, WriterInstanceID: first.WriterInstanceID}
	if err := identity.Validate(); err != nil {
		return identity, err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return identity, err
		}
		if entry.SessionID != identity.SessionID || recorder.ComputeHash(entry) != entry.Hash {
			return identity, errors.New("mixed session or recorder hash mismatch")
		}
	}
	last := entries[len(entries)-1]
	if last.Type != "checkpoint" || last.Sequence != env.Chain.CheckpointSeq || last.Hash != env.Chain.CheckpointHash {
		return identity, errors.New("checkpoint binding mismatch")
	}
	var checkpoint recorder.CheckpointDetail
	if json.Unmarshal(last.RawDetail, &checkpoint) != nil || checkpoint.Signature == "" || conductorcore.SignaturePrefixEd25519+strings.TrimPrefix(checkpoint.Signature, conductorcore.SignaturePrefixEd25519) != env.Chain.CheckpointSignature {
		return identity, errors.New("checkpoint signature binding mismatch")
	}
	return identity, nil
}

func (a *aggregator) addReceipt(instanceID string, ar receipt.ActionRecord) {
	a.totalActions++
	a.mediatedActions++
	increment(a.byFollower, valueOrUnspecified(instanceID))
	increment(a.byTransport, valueOrUnspecified(ar.Transport))
	increment(a.byActionType, valueOrUnspecified(string(ar.ActionType)))
	increment(a.byVerdict, valueOrUnspecified(ar.Verdict))
	increment(a.byLayer, valueOrUnspecified(ar.Layer))
	increment(a.bySeverity, valueOrUnspecified(ar.Severity))
}

func increment(counts map[string]uint64, key string) {
	counts[key]++
}

func valueOrUnspecified(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unspecified"
	}
	return value
}

func sourceBatch(ev controlplane.AuditBatchEvidence) fleetreceipt.SourceBatch {
	env := ev.Envelope
	return fleetreceipt.SourceBatch{
		OrgID:           env.OrgID,
		FleetID:         env.FleetID,
		InstanceID:      env.InstanceID,
		BatchID:         env.BatchID,
		SeqStart:        env.SeqStart,
		SeqEnd:          env.SeqEnd,
		EventCount:      env.EventCount,
		PayloadSHA256:   env.PayloadSHA256,
		PayloadBytes:    env.PayloadBytes,
		EnvelopeHash:    ev.Summary.EnvelopeHash,
		SegmentTailHash: env.Chain.SegmentTailHash,
		DroppedCount:    env.Dropped.Count,
		EmittedAt:       env.EmittedAt.UTC().Format(time.RFC3339),
		ReceivedAt:      ev.Summary.ReceivedAt.UTC().Format(time.RFC3339),
		SignatureKeyIDs: append([]string(nil), ev.Summary.SignatureKeyIDs...),
	}
}

func sourceBatchSubjectName(b fleetreceipt.SourceBatch) string {
	return fmt.Sprintf("conductor-audit-batch:%s/%s/%s/%s", b.OrgID, b.FleetID, b.InstanceID, b.BatchID)
}

func exactDecimalRatio(num, den uint64) (string, error) {
	if den == 0 {
		return "", fmt.Errorf("%w: zero denominator", ErrNonTerminatingRatio)
	}
	if num == 0 {
		return "0", nil
	}
	if num == den {
		return "1", nil
	}
	n := new(big.Int).SetUint64(num)
	d := new(big.Int).SetUint64(den)
	g := new(big.Int).GCD(nil, nil, n, d)
	n.Div(n, g)
	d.Div(d, g)

	two := big.NewInt(2)
	five := big.NewInt(5)
	ten := big.NewInt(10)
	places := 0
	rem := new(big.Int)
	for {
		quotient, remainder := new(big.Int).QuoRem(d, two, rem)
		if remainder.Sign() != 0 {
			break
		}
		d = quotient
		places++
	}
	for {
		quotient, remainder := new(big.Int).QuoRem(d, five, rem)
		if remainder.Sign() != 0 {
			break
		}
		d = quotient
		places++
	}
	if d.Cmp(big.NewInt(1)) != 0 {
		return "", ErrNonTerminatingRatio
	}
	scale := new(big.Int).Exp(ten, big.NewInt(int64(places)), nil)
	scaled := new(big.Int).Mul(n, scale)
	scaled.Div(scaled, new(big.Int).Div(new(big.Int).SetUint64(den), g))
	if places == 0 {
		return scaled.String(), nil
	}
	digits := scaled.String()
	for len(digits) <= places {
		digits = "0" + digits
	}
	head := digits[:len(digits)-places]
	tail := strings.TrimRight(digits[len(digits)-places:], "0")
	if head == "" {
		head = "0"
	}
	if tail == "" {
		return head, nil
	}
	return head + "." + tail, nil
}
