// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

type decisionIndex struct {
	ctx    context.Context
	tx     *sql.Tx
	ids    map[string]bool
	pieces map[string]pieceEntry
	disk   bool
	maxIDs int
	full   bool
}

type pieceEntry struct {
	Decision decisionPiece
	Failed   bool
}

func (d *decisionIndex) reset() error {
	const resetIndex = "DELETE FROM decision_ids; DELETE FROM decision_pieces; DELETE FROM hold_owners; DELETE FROM bad_shapes"
	_, err := d.tx.ExecContext(d.ctx, resetIndex)
	if err != nil {
		return fmt.Errorf("reset decision index: %w", err)
	}
	d.full = false
	if !d.disk {
		d.ids = make(map[string]bool)
	}
	return nil
}

func (d *decisionIndex) remember(id string, opaque bool) error {
	if d.disk {
		const query = "INSERT INTO decision_ids VALUES (?,?) ON CONFLICT (id) DO UPDATE SET opaque = opaque OR excluded.opaque"
		if _, err := d.tx.ExecContext(d.ctx, query, id, opaque); err != nil {
			return fmt.Errorf("index decision identifier: %w", err)
		}
		return nil
	}
	if previous, found := d.ids[id]; found {
		d.ids[id] = previous || opaque
	} else if len(d.ids) < d.maxIDs {
		d.ids[id] = opaque
	} else {
		d.full = true
	}
	return nil
}

func (d *decisionIndex) opaque(id string) (bool, error) {
	if !d.disk {
		return d.ids[id], nil
	}
	var opaque bool
	if err := d.tx.QueryRowContext(d.ctx, "SELECT opaque FROM decision_ids WHERE id=?", id).Scan(&opaque); err != nil {
		return false, fmt.Errorf("look up decision identifier: %w", err)
	}
	return opaque, nil
}

func (d *decisionIndex) beginSegment() error {
	if !d.disk {
		d.pieces = make(map[string]pieceEntry)
		return nil
	}
	if _, err := d.tx.ExecContext(d.ctx, "DELETE FROM decision_pieces"); err != nil {
		return fmt.Errorf("clear connected decision state: %w", err)
	}
	return nil
}

func (d *decisionIndex) get(id string) (pieceEntry, error) {
	if !d.disk {
		return d.pieces[id], nil
	}
	var data []byte
	if err := d.tx.QueryRowContext(d.ctx, "SELECT state FROM decision_pieces WHERE id=?", id).Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return pieceEntry{}, nil
		}
		return pieceEntry{}, fmt.Errorf("read connected decision state: %w", err)
	}
	return decodePiece(data)
}

func decodePiece(data []byte) (pieceEntry, error) {
	var entry pieceEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return entry, fmt.Errorf("decode connected decision state: %w", err)
	}
	return entry, nil
}

func (d *decisionIndex) put(id string, entry pieceEntry) error {
	if !d.disk {
		d.pieces[id] = entry
		return nil
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode connected decision state: %w", err)
	}
	if _, err := d.tx.ExecContext(d.ctx, "INSERT OR REPLACE INTO decision_pieces VALUES (?,?)", id, data); err != nil {
		return fmt.Errorf("store connected decision state: %w", err)
	}
	return nil
}

func (d *decisionIndex) eachPiece(apply func(pieceEntry)) error {
	if !d.disk {
		for _, entry := range d.pieces {
			apply(entry)
		}
		return nil
	}
	rows, err := d.tx.QueryContext(d.ctx, "SELECT state FROM decision_pieces")
	if err != nil {
		return fmt.Errorf("query connected decision states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return fmt.Errorf("read connected decision state: %w", err)
		}
		entry, err := decodePiece(data)
		if err != nil {
			return err
		}
		apply(entry)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate connected decision states: %w", err)
	}
	return nil
}

func (d *decisionIndex) badShape(segment int, id string) (bool, error) {
	var bad bool
	const query = "SELECT EXISTS (SELECT 1 FROM bad_shapes WHERE segment=? AND id=?)"
	if err := d.tx.QueryRowContext(d.ctx, query, segment, id).Scan(&bad); err != nil {
		return false, fmt.Errorf("look up decision shape: %w", err)
	}
	return bad, nil
}

func (d *decisionIndex) holdOwner(hold, action string) (string, error) {
	if _, err := d.tx.ExecContext(d.ctx, "INSERT OR IGNORE INTO hold_owners VALUES (?,?)", hold, action); err != nil {
		return "", fmt.Errorf("index hold identifier: %w", err)
	}
	var owner string
	if err := d.tx.QueryRowContext(d.ctx, "SELECT action_id FROM hold_owners WHERE id=?", hold).Scan(&owner); err != nil {
		return "", fmt.Errorf("look up hold identifier: %w", err)
	}
	return owner, nil
}

type appraisal struct {
	index         decisionIndex
	decisions     map[string]int64
	uninterpreted map[string]int64
	fullHistory   bool
}

func (v *verification) appraiseDecisions() error {
	tx, err := v.store.BeginTx(v.ctx, nil)
	if err != nil {
		return fmt.Errorf("start decision appraisal: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	a := appraisal{
		index:     decisionIndex{ctx: v.ctx, tx: tx, disk: v.opts.DiskIndex, maxIDs: maxDecisions},
		decisions: map[string]int64{}, uninterpreted: map[string]int64{}, fullHistory: true,
	}
	for _, lineage := range sortedKeys(v.histories) {
		members := v.histories[lineage]
		pieces := v.segments(members)
		if err := a.index.reset(); err != nil {
			return err
		}
		if err := v.appraiseHistory(&a, pieces, members[0]); err != nil {
			return err
		}
	}
	v.result.Counts = a.counts()
	return nil
}

func (v *verification) appraiseHistory(a *appraisal, pieces []segment, first *verifiedStream) error {
	complete := len(pieces) == 1 && pieces[0].rooted && len(pieces[0].streams[len(pieces[0].streams)-1].contenders) == 0
	a.fullHistory = a.fullHistory && complete
	future := false
	for _, piece := range pieces {
		for _, stream := range piece.streams {
			err := walkRecords(v.ctx, a.index.tx, stream.open.Stream, stream.limit, func(r stagedRecord) error {
				if r.Kind != kindAction {
					if r.unknown && !wireKinds[r.Kind].control {
						a.uninterpreted[r.Kind]++
						v.add(r.finding(codeEventUninterpreted))
					}
					return nil
				}
				if r.BodyV != wireKinds[kindAction].version {
					future = true
					a.uninterpreted[kindAction]++
					return nil
				}
				return v.inspectAction(a, stream, r)
			})
			if err != nil {
				return err
			}
		}
	}
	if future {
		v.add(first.open.finding(codeDecisionsNotAppraised))
	}
	if a.index.full {
		v.add(first.open.finding(codeDecisionIndexFull))
		if !slices.Contains(v.result.Limits, "L-DECISION-INDEX") {
			v.result.Limits = append(v.result.Limits, "L-DECISION-INDEX")
		}
	}
	if future || a.index.full {
		a.fullHistory = false
		return nil
	}
	for _, piece := range pieces {
		if err := v.appraiseSegment(a, piece); err != nil {
			return err
		}
	}
	return nil
}

func (v *verification) inspectAction(a *appraisal, stream *verifiedStream, r stagedRecord) error {
	body, err := unmarshalBody[Action](r)
	if err != nil {
		return err
	}
	if binding := body.Normalization; v.skip != codeNormalizationUnknown && binding != nil && normalizationProfiles[binding.Digest] != binding.ID {
		v.add(r.finding(codeNormalizationUnknown))
	}
	if err := a.index.remember(body.ActionID, r.unknown); err != nil {
		return err
	}
	if body.Hold != nil && (body.Phase == "hold" || body.Phase == "resolution") {
		owner, err := a.index.holdOwner(body.Hold.ID, body.ActionID)
		if err != nil {
			return err
		}
		if owner != body.ActionID {
			v.add(r.finding(codeDecisionInconsistent))
		}
	}
	switch {
	case r.unknown:
		a.uninterpreted[kindAction]++
		v.add(r.finding(codeActionUninterpreted))
	case !actionShape(body, stream.body.Coverage.ReceiptsRequired):
		v.add(r.finding(codeDecisionInconsistent))
		const query = "INSERT OR IGNORE INTO bad_shapes VALUES (?,?)"
		if _, err := a.index.tx.ExecContext(v.ctx, query, stream.segment, body.ActionID); err != nil {
			return fmt.Errorf("index malformed decision piece: %w", err)
		}
	}
	return nil
}

func (v *verification) appraiseSegment(a *appraisal, piece segment) error {
	if err := a.index.beginSegment(); err != nil {
		return err
	}
	for _, stream := range piece.streams {
		err := walkRecords(v.ctx, a.index.tx, stream.open.Stream, stream.limit, func(r stagedRecord) error {
			if r.Kind != kindAction {
				return nil
			}
			return v.stepDecision(&a.index, stream.segment, !piece.rooted, r)
		})
		if err != nil {
			return err
		}
	}
	if !piece.rooted {
		return nil
	}
	return a.index.eachPiece(func(entry pieceEntry) {
		if !entry.Failed {
			a.decisions[entry.Decision.State]++
		}
	})
}

func (v *verification) stepDecision(d *decisionIndex, segment int, unknownStart bool, r stagedRecord) error {
	action, err := unmarshalBody[Action](r)
	if err != nil {
		return err
	}
	entry, err := d.get(action.ActionID)
	if err != nil || entry.Failed {
		return err
	}
	if entry.Decision.State == "" {
		opaque, err := d.opaque(action.ActionID)
		if err != nil {
			return err
		}
		if opaque {
			entry.Decision.State = "uninterpreted"
		} else {
			bad, err := d.badShape(segment, action.ActionID)
			if err != nil {
				return err
			}
			entry.Failed = bad
		}
	}
	if v.skip == codeDecisionInconsistent {
		return nil
	}
	if !entry.Failed && entry.Decision.State != "uninterpreted" && !entry.Decision.advance(action, unknownStart) {
		entry.Failed = true
		v.add(r.finding(codeDecisionInconsistent))
	}
	return d.put(action.ActionID, entry)
}

func (a appraisal) counts() Counts {
	if !a.fullHistory {
		return Counts{Scope: "not_appraised"}
	}
	states := make([]StateCount, 0, len(a.decisions))
	unknown := int64(0)
	for _, state := range sortedKeys(a.decisions) {
		count := a.decisions[state]
		states = append(states, StateCount{Count: count, State: state})
		switch state {
		case "outcome_unknown", "pending", "asked_unobserved", "allowed_effect_unrecorded", "uninterpreted":
			unknown += count
		}
	}
	kinds := make([]KindCount, 0, len(a.uninterpreted))
	for _, kind := range sortedKeys(a.uninterpreted) {
		kinds = append(kinds, KindCount{Count: a.uninterpreted[kind], Kind: kind})
	}
	completed := a.decisions["completed"]
	return Counts{
		Scope: "full_history", Decisions: &states, EffectsCompleted: &completed,
		EffectsUnknown: &unknown, Uninterpreted: &kinds,
	}
}
