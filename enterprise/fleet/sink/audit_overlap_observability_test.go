//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0

package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAcceptedOverlapObservability(t *testing.T) {
	handler, store, priv := testHandler(t)
	var logs bytes.Buffer
	handler, err := NewHandler(Options{
		Store: store, Resolver: handler.resolver, DLPScanner: handler.dlpScanner,
		Now: handler.now, Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	post := func(id, session string, start uint64, version int) *httptest.ResponseRecorder {
		env, payload := sessionEnvelope(t, priv, id, session, start, version)
		return postBatch(t, handler, env, payload)
	}
	check := func(want uint64) {
		t.Helper()
		if got := handler.sessionFirstObservedCount.Load(); got != want {
			t.Fatalf("overlap count=%d want %d", got, want)
		}
		var events uint64
		for _, line := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var event map[string]any
			if err := json.Unmarshal(line, &event); err != nil {
				t.Fatal(err)
			}
			if event["event"] != "conductor_audit_session_first_observed" {
				continue
			}
			events++
			if event["level"] != "WARN" || event["receiver"] != "fleet_sink" || event["batch_id"] == "" || event["org_id"] == "" || event["fleet_id"] == "" || event["instance_id"] == "" || event["seq_start"] == nil || event["seq_end"] == nil {
				t.Fatalf("invalid structured overlap event: %v", event)
			}
			if event["counter_scope"] != "handler_lifetime" || event["session_first_observed_count"] != float64(events) {
				t.Fatalf("invalid handler counter event: %v", event)
			}
			for _, forbidden := range []string{"payload", "session_id", "signatures"} {
				if _, ok := event[forbidden]; ok {
					t.Fatalf("event includes %s", forbidden)
				}
			}
		}
		if events != want {
			t.Fatalf("warning count=%d want %d", events, want)
		}
	}
	for _, step := range []struct {
		id, session     string
		start           uint64
		version, status int
		count           uint64
	}{
		{"first", "run-a", 0, 2, http.StatusAccepted, 1},
		{"second", "run-b", 0, 2, http.StatusAccepted, 2},
		{"second", "run-b", 0, 2, http.StatusAccepted, 2},
		// This scan can exempt run-a before finding the later run-b fork.
		{"fork", "run-b", 0, 2, http.StatusConflict, 2},
		{"nonoverlap", "run-a", 10, 2, http.StatusAccepted, 2},
		// A new session counts once regardless of overlap fanout.
		{"third", "run-c", 0, 2, http.StatusAccepted, 3},
		// Validated v3 sessions are counted too.
		{"v3-first", "run-d", 20, 3, http.StatusAccepted, 4},
		{"v3-second", "run-e", 20, 3, http.StatusAccepted, 5},
	} {
		response := post(step.id, step.session, step.start, step.version)
		if response.Code != step.status {
			t.Fatalf("%s status=%d body=%s", step.id, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "SessionFirstObserved") || strings.Contains(response.Body.String(), "session_first_observed_count") {
			t.Fatal("internal observability leaked into response")
		}
		check(step.count)
	}

	// The INSERT succeeds, but a deferred FK violation rejects COMMIT. An
	// exemption observed before that failure must never become an acceptance.
	for _, sql := range []string{
		"PRAGMA foreign_keys = ON",
		"CREATE TABLE overlap_guard_parent (id INTEGER PRIMARY KEY)",
		"CREATE TABLE overlap_guard (id INTEGER REFERENCES overlap_guard_parent(id) DEFERRABLE INITIALLY DEFERRED)",
		"CREATE TRIGGER fail_overlap_commit AFTER INSERT ON audit_batches BEGIN INSERT INTO overlap_guard VALUES(1); END",
	} {
		if _, err := store.db.ExecContext(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	response := post("commit-failed", "run-f", 0, 2)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("commit failure status=%d body=%s", response.Code, response.Body.String())
	}
	check(5)
	var failedRows int
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM audit_batches WHERE batch_id = 'commit-failed'").Scan(&failedRows); err != nil || failedRows != 0 {
		t.Fatalf("failed transaction persisted rows=%d err=%v", failedRows, err)
	}
	for _, table := range []string{"audit_session_observations", "audit_chain_observations"} {
		if err := store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table+" WHERE session_id='run-f'").Scan(&failedRows); err != nil || failedRows != 0 {
			t.Fatalf("failed transaction persisted %s rows=%d err=%v", table, failedRows, err)
		}
	}
	if _, err := store.db.ExecContext(context.Background(), "DROP TRIGGER fail_overlap_commit"); err != nil {
		t.Fatal(err)
	}
	// Recovery accepts exactly once, proving the failed call emitted nothing.
	if response := post("commit-failed", "run-f", 0, 2); response.Code != http.StatusAccepted {
		t.Fatalf("recovery status=%d body=%s", response.Code, response.Body.String())
	}
	check(6)
}

// Concurrent retries must count only the winning durable INSERT. Different
// sessions must each count once even if log writes reach the collector out of
// commit order; the handler-lifetime count is atomic, not a delivery ordering.
func TestConcurrentAcceptedOverlapCounter(t *testing.T) {
	for _, mode := range []string{"distinct-sessions", "duplicate", "same-session"} {
		t.Run(mode, func(t *testing.T) {
			handler, store, priv := testHandler(t)
			var logs bytes.Buffer
			handler, err := NewHandler(Options{
				Store: store, Resolver: handler.resolver, DLPScanner: handler.dlpScanner,
				Now: handler.now, Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			env, payload := sessionEnvelope(t, priv, "seed", "run-seed", 0, 2)
			if response := postBatch(t, handler, env, payload); response.Code != http.StatusAccepted {
				t.Fatal(response.Body.String())
			}
			const deliveries = 6
			requests := make([]*http.Request, deliveries)
			for i := range requests {
				id := i
				if mode == "duplicate" {
					id = 0
				}
				session, start := fmt.Sprintf("run-%d", id), uint64(0)
				if mode == "same-session" {
					session, start = "one-session", uint64(i)*10
				}
				env, payload := sessionEnvelope(t, priv, fmt.Sprintf("batch-%d", id), session, start, 2)
				body, err := json.Marshal(uploadRequest{Envelope: env, Payload: payload})
				if err != nil {
					t.Fatal(err)
				}
				requests[i] = httptest.NewRequestWithContext(context.Background(), http.MethodPost, AuditBatchesPath, bytes.NewReader(body))
				requests[i].Header.Set("Content-Type", "application/json")
			}
			responses := make(chan *httptest.ResponseRecorder, deliveries)
			for _, request := range requests {
				go func() {
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					responses <- response
				}()
			}
			for range deliveries {
				if response := <-responses; response.Code != http.StatusAccepted {
					t.Fatalf("concurrent status=%d body=%s", response.Code, response.Body.String())
				}
			}
			want := uint64(deliveries + 1)
			if mode != "distinct-sessions" {
				want = 2
			}
			if got := handler.sessionFirstObservedCount.Load(); got != want {
				t.Fatalf("overlap count=%d want %d", got, want)
			}
			seen := make(map[uint64]bool)
			for _, line := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")) {
				var event struct {
					Count uint64 `json:"session_first_observed_count"`
				}
				if err := json.Unmarshal(line, &event); err != nil {
					t.Fatal(err)
				}
				if event.Count == 0 || event.Count > want || seen[event.Count] {
					t.Fatalf("invalid or duplicate count %d", event.Count)
				}
				seen[event.Count] = true
			}
			if len(seen) != int(want) {
				t.Fatalf("distinct warning counts=%d want %d", len(seen), want)
			}
		})
	}
}
