//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditstate

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	_ "modernc.org/sqlite"
)

// No payload or envelope column exists here: a successful comparison proves
// conflict detection consumes only indexed retained metadata.
func metadataFixture(t testing.TB, payloadBytes int) (*sql.DB, conductor.AuditBatchEnvelope, conductor.AuditNamespace) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	ddl := `CREATE TABLE audit_batches(org_id TEXT,fleet_id TEXT,instance_id TEXT,batch_id TEXT,seq_start TEXT,seq_end TEXT,payload_sha256 TEXT,segment_tail_hash TEXT,PRIMARY KEY(org_id,fleet_id,instance_id,batch_id));
 CREATE INDEX idx_conductor_audit_batches_namespace_sequence ON audit_batches(org_id,fleet_id,instance_id,seq_start,seq_end);`
	if _, err = db.ExecContext(context.Background(), ddl+stateDDL); err != nil {
		t.Fatal(err)
	}
	if payloadBytes > 0 {
		if _, err = db.ExecContext(context.Background(), "ALTER TABLE audit_batches ADD COLUMN payload_blob BLOB"); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 40 {
		id := fmt.Sprintf("batch-%d", i)
		if payloadBytes == 0 {
			if _, err = db.ExecContext(context.Background(), "INSERT INTO audit_batches VALUES(?,?,?,?,?,?,?,?)", "org", "fleet", "follower", id, sequence(0), sequence(1), id, id); err != nil {
				t.Fatal(err)
			}
		}
		if payloadBytes > 0 {
			if _, err = db.ExecContext(context.Background(), "INSERT INTO audit_batches(org_id,fleet_id,instance_id,batch_id,seq_start,seq_end,payload_sha256,segment_tail_hash,payload_blob) VALUES(?,?,?,?,?,?,?,?,zeroblob(?))", "org", "fleet", "follower", id, sequence(0), sequence(1), id, id, payloadBytes); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = db.ExecContext(context.Background(), "INSERT INTO audit_batch_namespaces VALUES(?,?,?,?,?,?,?,?)", "org", "fleet", "follower", id, 2, id, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	return db, conductor.AuditBatchEnvelope{OrgID: "org", FleetID: "fleet", InstanceID: "follower", SeqStart: 0, SeqEnd: 1, PayloadSHA256: "incoming", Chain: conductor.EvidenceChain{SegmentTailHash: "incoming"}}, conductor.AuditNamespace{EntryVersion: 2, SessionID: "incoming"}
}

func TestConflictMetadataOnly(t *testing.T) {
	db, env, ns := metadataFixture(t, 0)
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	conflict, err := Conflict(t.Context(), tx, env, ns)
	if err != nil || conflict {
		t.Fatalf("distinct namespaces conflict=%t err=%v", conflict, err)
	}
	ns.SessionID = "batch-0"
	conflict, err = Conflict(t.Context(), tx, env, ns)
	if err != nil || !conflict {
		t.Fatalf("same namespace conflict=%t err=%v", conflict, err)
	}
	rows, err := tx.QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+conflictSQL, env.OrgID, env.FleetID, env.InstanceID, sequence(env.SeqStart), sequence(env.SeqEnd))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	indexed := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err = rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		t.Log(detail)
		indexed = indexed || strings.Contains(detail, "SEARCH b USING INDEX idx_conductor_audit_batches_namespace_sequence")
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !indexed {
		t.Fatal("overlap lookup did not use namespace sequence index")
	}
}

// Comparator cost only; excludes incoming validation, persistence and migration.
func BenchmarkConflictRetainedMetadata(b *testing.B) {
	db, env, ns := metadataFixture(b, 1<<20)
	tx, err := db.BeginTx(b.Context(), nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	b.ResetTimer()
	for b.Loop() {
		if conflict, err := Conflict(b.Context(), tx, env, ns); err != nil || conflict {
			b.Fatalf("conflict=%t err=%v", conflict, err)
		}
	}
}
