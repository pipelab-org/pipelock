//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

func TestSessionObservationMigrationRollbackAndRecovery(t *testing.T) {
	for _, failure := range []string{"record_write", "received_at"} {
		t.Run(failure, func(t *testing.T) {
			pub, priv := testAuditSigner(t)
			path := filepath.Join(t.TempDir(), "audit.db")
			store := openTestSQLiteAuditStore(t, path)
			handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
			for _, id := range []string{"a", "b"} {
				if got := auditRunPost(t, handler, controlplaneSessionBatch(t, priv, id, "run-"+id, 0, 2)).Code; got != http.StatusAccepted {
					t.Fatalf("%s status=%d", id, got)
				}
			}
			var received time.Time
			if err := store.db.QueryRowContext(t.Context(), "SELECT received_at FROM audit_batches WHERE batch_id='b'").Scan(&received); err != nil {
				t.Fatal(err)
			}
			// Leave retained evidence unclassified, as at first upgrade. Fail the
			// second row so a non-atomic migration would leave the first behind.
			tables := []string{"audit_batch_namespaces", "audit_session_observations", "audit_chain_observations", "audit_observation_coverage"}
			for _, statement := range []string{
				"DELETE FROM audit_batch_namespaces",
				"DELETE FROM audit_session_observations",
				"DELETE FROM audit_chain_observations",
				"DELETE FROM audit_observation_coverage",
			} {
				if _, err := store.db.ExecContext(t.Context(), statement); err != nil {
					t.Fatal(err)
				}
			}
			breakSQL := "CREATE TRIGGER refuse_migration_row BEFORE INSERT ON audit_batch_namespaces WHEN NEW.batch_id='b' BEGIN SELECT RAISE(ABORT,'migration write refused'); END"
			repairSQL := "DROP TRIGGER refuse_migration_row"
			if failure == "received_at" {
				breakSQL = "UPDATE audit_batches SET received_at='invalid' WHERE batch_id='b'"
				repairSQL = "UPDATE audit_batches SET received_at=? WHERE batch_id='b'"
			}
			if _, err := store.db.ExecContext(t.Context(), breakSQL); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			failed, err := OpenSQLiteAuditStore(t.Context(), path)
			if failed != nil {
				_ = failed.Close()
				t.Fatal("failed migration returned an open store")
			}
			if err == nil {
				t.Fatal("migration ignored a storage failure")
			}
			t.Logf("migration refused: %v", err)
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			for _, table := range tables {
				var n int
				if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 0 {
					t.Fatalf("partial %s rows=%d err=%v", table, n, err)
				}
			}
			var retained int
			if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM audit_batches").Scan(&retained); err != nil || retained != 2 {
				t.Fatalf("retained batches=%d err=%v", retained, err)
			}
			var args []any
			if failure == "received_at" {
				args = []any{received}
			}
			if _, err = db.ExecContext(t.Context(), repairSQL, args...); err != nil {
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = OpenSQLiteAuditStore(t.Context(), path)
			if err != nil {
				t.Fatalf("reopen after correcting storage failure: %v", err)
			}
			defer func() { _ = store.Close() }()
			var classified int
			if err = store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM audit_batch_namespaces WHERE session_id<>''").Scan(&classified); err != nil || classified != 2 {
				t.Fatalf("classified batches=%d err=%v", classified, err)
			}
			// Reopening classified history must not repeat payload classification.
			if _, err = store.db.ExecContext(t.Context(), "CREATE TRIGGER refuse_reclassification BEFORE INSERT ON audit_batch_namespaces BEGIN SELECT RAISE(ABORT,'reclassification'); END"); err != nil {
				t.Fatal(err)
			}
			if err = store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = OpenSQLiteAuditStore(t.Context(), path)
			if err != nil {
				t.Fatalf("classified history was revisited: %v", err)
			}
		})
	}
}

func TestSessionObservationsMigrationAndPrune(t *testing.T) {
	pub, priv := testAuditSigner(t)
	path := filepath.Join(t.TempDir(), "audit.db")
	store := openTestSQLiteAuditStore(t, path)
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
	post := func(id, session string, start uint64, version int) int {
		return auditRunPost(t, handler, controlplaneSessionBatch(t, priv, id, session, start, version)).Code
	}

	var err error

	defer func() { _ = store.Close() }()
	check := func(sessions, chains int) {
		t.Helper()
		var n int
		for table, want := range map[string]int{"audit_session_observations": sessions, "audit_chain_observations": chains} {
			if e := store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&n); e != nil || n != want {
				t.Fatalf("%s rows=%d want=%d err=%v", table, n, want, e)
			}
		}
	}
	for _, step := range []struct {
		id, session   string
		start         uint64
		version, want int
	}{
		{"a", "run-a", 0, 2, http.StatusAccepted}, {"a", "run-a", 0, 2, http.StatusAccepted}, {"a-next", "run-a", 10, 2, http.StatusAccepted}, {"b", "run-b", 0, 3, http.StatusAccepted}, {"b-fork", "run-b", 0, 3, http.StatusConflict},
	} {
		if got := post(step.id, step.session, step.start, step.version); got != step.want {
			t.Fatalf("%s status=%d want=%d", step.id, got, step.want)
		}
	}
	check(2, 2)
	// Simulate the pre-observation schema while preserving accepted evidence.
	for _, ddl := range []string{"DROP TRIGGER audit_namespace_invalidate", "DROP TABLE audit_batch_namespaces", "DROP TABLE audit_session_observations", "DROP TABLE audit_chain_observations", "DROP TABLE audit_observation_coverage"} {
		if _, e := store.db.ExecContext(t.Context(), ddl); e != nil {
			t.Fatal(e)
		}
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSQLiteAuditStore(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	handler.auditSink = store
	check(2, 2)
	var backfill int
	if err = store.db.QueryRowContext(t.Context(), "SELECT min(retained_backfill) FROM audit_session_observations").Scan(&backfill); err != nil || backfill != 1 {
		t.Fatalf("backfill=%d err=%v", backfill, err)
	}
	var originalFirst string
	if err = store.db.QueryRowContext(t.Context(), "SELECT first_received FROM audit_chain_observations WHERE session_id=?", "run-a").Scan(&originalFirst); err != nil {
		t.Fatal(err)
	}
	_, err = store.PruneAuditBatchesBefore(t.Context(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	check(2, 2)
	var remaining int
	if err = store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM audit_batches").Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("remaining=%d err=%v", remaining, err)
	}
	var before string
	if err = store.db.QueryRowContext(t.Context(), "SELECT pruned_before FROM audit_observation_coverage WHERE id=1").Scan(&before); err != nil || before == "" {
		t.Fatalf("prune coverage=%q err=%v", before, err)
	}
	// Reusing a pruned batch ID must insert its namespace again. A subsequent
	// identical retry must skip that insertion and remain idempotent.
	for attempt, want := range []string{`"status":"accepted"`, `"status":"duplicate"`} {
		response := auditRunPost(t, handler, controlplaneSessionBatch(t, priv, "a-next", "run-a", 10, 2))
		if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), want) {
			t.Fatalf("pruned batch retry %d status=%d body=%s want=%s", attempt, response.Code, response.Body.String(), want)
		}
	}
	var namespaces int
	if err = store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM audit_batch_namespaces WHERE batch_id='a-next'").Scan(&namespaces); err != nil || namespaces != 1 {
		t.Fatalf("retried batch namespaces=%d want=1 err=%v", namespaces, err)
	}
	if got := post("a-after-prune", "run-a", 20, 2); got != http.StatusAccepted {
		t.Fatalf("post-prune status=%d", got)
	}
	check(2, 2)
	// Pruned payloads no longer supply same-chain conflict comparisons. Arrival
	// observations survive, but don't prove the deleted sequence history.
	if got := post("a-pruned-overlap-known-limitation", "run-a", 0, 2); got != http.StatusAccepted {
		t.Fatalf("pruned overlap status=%d", got)
	}
	var after, firstReceived, seqStart string
	if err = store.db.QueryRowContext(t.Context(), "SELECT pruned_before FROM audit_observation_coverage WHERE id=1").Scan(&after); err != nil || after != before {
		t.Fatalf("post-overlap prune coverage=%q want=%q err=%v", after, before, err)
	}
	if err = store.db.QueryRowContext(t.Context(), "SELECT first_received,seq_start FROM audit_chain_observations WHERE session_id=?", "run-a").Scan(&firstReceived, &seqStart); err != nil {
		t.Fatal(err)
	}
	if firstReceived != originalFirst || seqStart != formatAuditUint(0) {
		t.Fatalf("post-overlap observation first=%q want=%q seq_start=%q", firstReceived, originalFirst, seqStart)
	}
}

func TestSessionObservationsConcurrentBatches(t *testing.T) {
	pub, priv := testAuditSigner(t)
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	t.Cleanup(func() { _ = store.Close() })
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
	handler.metrics = metrics.New()
	const deliveries = 6
	requests := make([]*http.Request, deliveries)
	for i := range requests {
		batch := controlplaneSessionBatch(t, priv, fmt.Sprintf("batch-%d", i), "one-session", uint64(i)*10, 2)
		body, err := json.Marshal(ingestAuditBatchRequest{Envelope: batch.Envelope, Payload: batch.Payload})
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = httptest.NewRequestWithContext(t.Context(), http.MethodPost, AuditBatchesPath, bytes.NewReader(body))
		requests[i].Header.Set("Content-Type", "application/json")
	}
	statuses := make(chan int, deliveries)
	for _, request := range requests {
		go func() {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			statuses <- response.Code
		}()
	}
	for range deliveries {
		if got := <-statuses; got != http.StatusAccepted {
			t.Fatalf("status=%d", got)
		}
	}
	var count int
	if err := store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM audit_session_observations").Scan(&count); err != nil || count != 1 {
		t.Fatalf("sessions=%d err=%v", count, err)
	}
	response := httptest.NewRecorder()
	handler.metrics.PrometheusHandler().ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if !strings.Contains(response.Body.String(), "pipelock_conductor_server_audit_session_first_observed_total 1\n") {
		t.Fatal("first observation must be emitted once")
	}
}

func TestSessionObservationsArrivalRange(t *testing.T) {
	pub, priv := testAuditSigner(t)
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	t.Cleanup(func() { _ = store.Close() })
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
	times := []time.Time{testNow.Add(900 * time.Millisecond), testNow, testNow.Add(100 * time.Millisecond)}
	for i, at := range times {
		handler.now = func() time.Time { return at }
		batch := controlplaneSessionBatch(t, priv, fmt.Sprintf("arrival-%d", i), "arrival-session", uint64(i)*10, 2)
		if response := auditRunPost(t, handler, batch); response.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
	for _, table := range []string{"audit_session_observations", "audit_chain_observations"} {
		var first, last string
		if err := store.db.QueryRowContext(t.Context(), "SELECT first_received,last_received FROM "+table+" WHERE session_id='arrival-session'").Scan(&first, &last); err != nil {
			t.Fatal(err)
		}
		if first != times[1].Format(time.RFC3339Nano) || last != times[0].Format(time.RFC3339Nano) {
			t.Fatalf("%s range=%s..%s", table, first, last)
		}
	}
}
