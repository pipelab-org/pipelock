//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import (
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionObservationsMigrationAndPrune(t *testing.T) {
	handler, _, priv := testHandler(t)
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := OpenStore(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	handler.store = store
	post := func(id, session string, start uint64, version int) int {
		env, payload := sessionEnvelope(t, priv, id, session, start, version)
		return postBatch(t, handler, env, payload).Code
	}

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
	store, err = OpenStore(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	handler.store = store
	check(2, 2)
	var backfill int
	if err = store.db.QueryRowContext(t.Context(), "SELECT min(retained_backfill) FROM audit_session_observations").Scan(&backfill); err != nil || backfill != 1 {
		t.Fatalf("backfill=%d err=%v", backfill, err)
	}
	_, err = store.PruneBefore(t.Context(), time.Now().Add(time.Hour))
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
	if got := post("a-after-prune", "run-a", 20, 2); got != http.StatusAccepted {
		t.Fatalf("post-prune status=%d", got)
	}
	check(2, 2)
}

func TestSessionObservationsArrivalRange(t *testing.T) {
	handler, store, priv := testHandler(t)
	times := []time.Time{sinkTestNow.Add(900 * time.Millisecond), sinkTestNow, sinkTestNow.Add(100 * time.Millisecond)}
	for i, at := range times {
		handler.now = func() time.Time { return at }
		env, payload := sessionEnvelope(t, priv, fmt.Sprintf("arrival-%d", i), "arrival-session", uint64(i)*10, 2)
		if response := postBatch(t, handler, env, payload); response.Code != http.StatusAccepted {
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
