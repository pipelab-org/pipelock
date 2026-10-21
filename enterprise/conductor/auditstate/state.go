//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package auditstate keeps receiver observations separately from retained payloads.
// Observations establish arrival facts, not cross-session continuity.
package auditstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

const stateDDL = `
CREATE TABLE IF NOT EXISTS audit_batch_namespaces (
 org_id TEXT NOT NULL, fleet_id TEXT NOT NULL, instance_id TEXT NOT NULL, batch_id TEXT NOT NULL,
 entry_version INTEGER NOT NULL, session_id TEXT NOT NULL, chain_kind TEXT NOT NULL, writer_id TEXT NOT NULL,
 PRIMARY KEY(org_id,fleet_id,instance_id,batch_id));
CREATE TABLE IF NOT EXISTS audit_session_observations (
 org_id TEXT NOT NULL, fleet_id TEXT NOT NULL, instance_id TEXT NOT NULL, session_id TEXT NOT NULL,
 first_received TEXT NOT NULL, last_received TEXT NOT NULL, retained_backfill INTEGER NOT NULL,
 PRIMARY KEY(org_id,fleet_id,instance_id,session_id));
CREATE TABLE IF NOT EXISTS audit_chain_observations (
 org_id TEXT NOT NULL, fleet_id TEXT NOT NULL, instance_id TEXT NOT NULL,
 entry_version INTEGER NOT NULL, session_id TEXT NOT NULL, chain_kind TEXT NOT NULL, writer_id TEXT NOT NULL,
 first_received TEXT NOT NULL, last_received TEXT NOT NULL, seq_start TEXT NOT NULL, seq_end TEXT NOT NULL,
 PRIMARY KEY(org_id,fleet_id,instance_id,entry_version,session_id,chain_kind,writer_id));
CREATE INDEX IF NOT EXISTS audit_batch_namespaces_chain ON audit_batch_namespaces
 (org_id,fleet_id,instance_id,entry_version,session_id,chain_kind,writer_id);
CREATE TRIGGER IF NOT EXISTS audit_namespace_invalidate AFTER UPDATE ON audit_batches
BEGIN
 DELETE FROM audit_batch_namespaces WHERE org_id=OLD.org_id AND fleet_id=OLD.fleet_id AND instance_id=OLD.instance_id AND batch_id=OLD.batch_id;
 UPDATE audit_observation_coverage SET history_unknown=1 WHERE id=1;
END;
CREATE TABLE IF NOT EXISTS audit_observation_coverage (
 id INTEGER PRIMARY KEY CHECK(id=1), observations_since TEXT NOT NULL, history_unknown INTEGER NOT NULL,
 pruned_before TEXT NOT NULL DEFAULT '');
`

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func sequence(n uint64) string { return fmt.Sprintf("%020d", n) }

// Migrate atomically backfills retained evidence. Unresolvable rows retain an
// explicit zero identity, so an indexed lookup cannot silently skip them.
func Migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, stateDDL); err != nil {
		return fmt.Errorf("migrate audit observations: %w", err)
	}
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_batches`).Scan(&n); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_observation_coverage(id,observations_since,history_unknown) VALUES(1,?,?) ON CONFLICT(id) DO NOTHING`, stamp(time.Now()), n != 0); err != nil {
		return err
	}
	// Backfill one bounded payload at a time inside the atomic migration.
	var after int64
	for {
		var org, fleet, instance, batch string
		var raw, payload []byte
		var received time.Time
		err = tx.QueryRowContext(ctx, `SELECT b.rowid,b.org_id,b.fleet_id,b.instance_id,b.batch_id,b.envelope_json,CASE WHEN length(b.payload_blob)<=? THEN b.payload_blob ELSE NULL END,b.received_at FROM audit_batches b LEFT JOIN audit_batch_namespaces n USING(org_id,fleet_id,instance_id,batch_id) WHERE b.rowid>? AND n.batch_id IS NULL ORDER BY b.rowid LIMIT 1`, conductor.MaxAuditPayloadBytes, after).Scan(&after, &org, &fleet, &instance, &batch, &raw, &payload, &received)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		var env conductor.AuditBatchEnvelope
		ns := conductor.AuditNamespace{}
		if json.Unmarshal(raw, &env) == nil && env.OrgID == org && env.FleetID == fleet && env.InstanceID == instance && env.BatchID == batch {
			ns, err = env.PayloadNamespace(ctx, payload)
			if err != nil {
				return err
			}
		}
		env.OrgID, env.FleetID, env.InstanceID, env.BatchID = org, fleet, instance, batch
		if _, err = Record(ctx, tx, env, ns, received, true); err != nil {
			return err
		}
	}

	return tx.Commit()
}

const conflictSQL = `SELECT COALESCE(n.entry_version,0),COALESCE(n.session_id,''),COALESCE(n.chain_kind,''),COALESCE(n.writer_id,''),b.payload_sha256,b.segment_tail_hash FROM audit_batches b LEFT JOIN audit_batch_namespaces n USING(org_id,fleet_id,instance_id,batch_id) WHERE b.org_id=? AND b.fleet_id=? AND b.instance_id=? AND b.seq_end>=? AND b.seq_start<=?`

// Conflict compares retained evidence. Unknown identity cannot separate two
// overlapping histories, even when the unvalidated envelope labels differ.
func Conflict(ctx context.Context, tx *sql.Tx, env conductor.AuditBatchEnvelope, ns conductor.AuditNamespace) (bool, error) {
	rows, err := tx.QueryContext(ctx, conflictSQL, env.OrgID, env.FleetID, env.InstanceID, sequence(env.SeqStart), sequence(env.SeqEnd))
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var old conductor.AuditNamespace
		var digest, tail string
		if err = rows.Scan(&old.EntryVersion, &old.SessionID, &old.ChainKind, &old.WriterInstanceID, &digest, &tail); err != nil {
			return false, err
		}
		if digest == env.PayloadSHA256 && tail == env.Chain.SegmentTailHash {
			continue
		}
		if ns.SessionID != "" && old.SessionID != "" && ns != old {
			continue
		}
		return true, nil
	}
	return false, rows.Err()
}

// Record must run only for a newly inserted batch, in that insertion's transaction.
// The returned boolean denotes the unique follower/session's first observation.
func Record(ctx context.Context, tx *sql.Tx, env conductor.AuditBatchEnvelope, ns conductor.AuditNamespace, received time.Time, backfill bool) (bool, error) {
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_batch_namespaces VALUES(?,?,?,?,?,?,?,?)`, env.OrgID, env.FleetID, env.InstanceID, env.BatchID, ns.EntryVersion, ns.SessionID, ns.ChainKind, ns.WriterInstanceID); err != nil {
		return false, err
	}
	if ns.SessionID == "" {
		_, err := tx.ExecContext(ctx, `UPDATE audit_observation_coverage SET history_unknown=1 WHERE id=1`)
		return false, err
	}
	at := stamp(received)
	result, err := tx.ExecContext(ctx, `INSERT INTO audit_session_observations VALUES(?,?,?,?,?,?,?) ON CONFLICT(org_id,fleet_id,instance_id,session_id) DO NOTHING`, env.OrgID, env.FleetID, env.InstanceID, ns.SessionID, at, at, backfill)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	// Parse times rather than lexically ordering RFC3339's variable fractions.
	var first, last string
	if err = tx.QueryRowContext(ctx, `SELECT first_received,last_received FROM audit_session_observations WHERE org_id=? AND fleet_id=? AND instance_id=? AND session_id=?`, env.OrgID, env.FleetID, env.InstanceID, ns.SessionID).Scan(&first, &last); err != nil {
		return false, err
	}
	first, last, err = expand(first, last, received)
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE audit_session_observations SET first_received=?,last_received=? WHERE org_id=? AND fleet_id=? AND instance_id=? AND session_id=?`, first, last, env.OrgID, env.FleetID, env.InstanceID, ns.SessionID); err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_chain_observations VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(org_id,fleet_id,instance_id,entry_version,session_id,chain_kind,writer_id) DO UPDATE SET seq_start=min(seq_start,excluded.seq_start),seq_end=max(seq_end,excluded.seq_end)`, env.OrgID, env.FleetID, env.InstanceID, ns.EntryVersion, ns.SessionID, ns.ChainKind, ns.WriterInstanceID, at, at, sequence(env.SeqStart), sequence(env.SeqEnd))
	if err != nil {
		return false, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT first_received,last_received FROM audit_chain_observations WHERE org_id=? AND fleet_id=? AND instance_id=? AND entry_version=? AND session_id=? AND chain_kind=? AND writer_id=?`, env.OrgID, env.FleetID, env.InstanceID, ns.EntryVersion, ns.SessionID, ns.ChainKind, ns.WriterInstanceID).Scan(&first, &last); err != nil {
		return false, err
	}
	first, last, err = expand(first, last, received)
	if err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE audit_chain_observations SET first_received=?,last_received=? WHERE org_id=? AND fleet_id=? AND instance_id=? AND entry_version=? AND session_id=? AND chain_kind=? AND writer_id=?`, first, last, env.OrgID, env.FleetID, env.InstanceID, ns.EntryVersion, ns.SessionID, ns.ChainKind, ns.WriterInstanceID)
	return n == 1 && !backfill, err
}

func expand(first, last string, at time.Time) (string, string, error) {
	a, err := time.Parse(time.RFC3339Nano, first)
	if err != nil {
		return "", "", err
	}
	b, err := time.Parse(time.RFC3339Nano, last)
	if err != nil {
		return "", "", err
	}
	if at.Before(a) {
		first = stamp(at)
	}
	if at.After(b) {
		last = stamp(at)
	}
	return first, last, nil
}

// Prune removes payloads and their per-batch comparator metadata, retaining
// durable session observations and an explicit history-comparison limitation.
func Prune(ctx context.Context, db *sql.DB, before time.Time) (int64, error) {
	if ctx == nil || db == nil || before.IsZero() {
		return 0, errors.New("audit prune requires context, database and cutoff")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM audit_batches WHERE received_at < ?`, before.UTC())
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM audit_batch_namespaces WHERE NOT EXISTS(SELECT 1 FROM audit_batches b WHERE b.org_id=audit_batch_namespaces.org_id AND b.fleet_id=audit_batch_namespaces.fleet_id AND b.instance_id=audit_batch_namespaces.instance_id AND b.batch_id=audit_batch_namespaces.batch_id)`); err != nil {
		return 0, err
	}
	var previous string
	if err = tx.QueryRowContext(ctx, `SELECT pruned_before FROM audit_observation_coverage WHERE id=1`).Scan(&previous); err != nil {
		return 0, err
	}
	if previous != "" {
		old, e := time.Parse(time.RFC3339Nano, previous)
		if e != nil {
			return 0, e
		}
		if old.After(before) {
			before = old
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE audit_observation_coverage SET pruned_before=? WHERE id=1`, stamp(before)); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// Observation is receiver evidence about one validated recorder chain. Arrival
// order never establishes a predecessor relationship between sessions.
type Observation struct {
	InstanceID       string `json:"instanceId"`
	EntryVersion     int    `json:"entryVersion"`
	SessionID        string `json:"sessionId"`
	ChainKind        string `json:"chainKind,omitempty"`
	WriterInstanceID string `json:"writerInstanceId,omitempty"`
	FirstReceived    string `json:"firstReceived"`
	LastReceived     string `json:"lastReceived"`
	SeqStart         uint64 `json:"seqStart"`
	SeqEnd           uint64 `json:"seqEnd"`
	RetainedBackfill bool   `json:"retainedBackfill"`
}

type Coverage struct {
	ObservationsSince string `json:"observationsSince"`
	HistoryUnknown    bool   `json:"historyUnknown"`
	PrunedBefore      string `json:"prunedBefore,omitempty"`
}

// Query is called within the same read snapshot as the report's batch query.
func Query(ctx context.Context, tx *sql.Tx, org, fleet string) ([]Observation, Coverage, error) {
	var coverage Coverage
	if err := tx.QueryRowContext(ctx, `SELECT observations_since,history_unknown,pruned_before FROM audit_observation_coverage WHERE id=1`).Scan(&coverage.ObservationsSince, &coverage.HistoryUnknown, &coverage.PrunedBefore); err != nil {
		return nil, coverage, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT c.instance_id,c.entry_version,c.session_id,c.chain_kind,c.writer_id,c.first_received,c.last_received,c.seq_start,c.seq_end,s.retained_backfill FROM audit_chain_observations c JOIN audit_session_observations s USING(org_id,fleet_id,instance_id,session_id) WHERE c.org_id=? AND c.fleet_id=? ORDER BY c.instance_id,c.entry_version,c.session_id,c.chain_kind,c.writer_id`, org, fleet)
	if err != nil {
		return nil, coverage, err
	}
	defer func() { _ = rows.Close() }()
	var out []Observation
	for rows.Next() {
		var o Observation
		var start, end string
		if err = rows.Scan(&o.InstanceID, &o.EntryVersion, &o.SessionID, &o.ChainKind, &o.WriterInstanceID, &o.FirstReceived, &o.LastReceived, &start, &end, &o.RetainedBackfill); err != nil {
			return nil, coverage, err
		}
		o.SeqStart, err = strconv.ParseUint(start, 10, 64)
		if err != nil {
			return nil, coverage, err
		}
		o.SeqEnd, err = strconv.ParseUint(end, 10, 64)
		if err != nil {
			return nil, coverage, err
		}
		out = append(out, o)
	}
	return out, coverage, rows.Err()
}
