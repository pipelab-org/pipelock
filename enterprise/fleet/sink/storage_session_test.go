//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func sessionEnvelope(t *testing.T, priv ed25519.PrivateKey, id, session string, start uint64, version int) (conductor.AuditBatchEnvelope, []byte) {
	t.Helper()
	entries := []recorder.Entry{
		{Version: version, Sequence: start, Timestamp: sinkTestNow, SessionID: session, Type: "capture", Summary: id, PrevHash: recorder.GenesisHash},
		{Version: version, Sequence: start + 1, Timestamp: sinkTestNow, SessionID: session, Type: "checkpoint"},
	}
	if version == 3 {
		for i := range entries {
			entries[i].ChainKind = "proxy"
			entries[i].WriterInstanceID = "writer-1"
		}
	}
	entries[0].Hash = recorder.ComputeHash(entries[0])
	entries[1].PrevHash = entries[0].Hash
	sig := hex.EncodeToString(ed25519.Sign(priv, []byte(entries[1].PrevHash)))
	entries[1].Detail = recorder.CheckpointDetail{Signature: sig, EntryCount: 1, FirstSeq: start, LastSeq: start}
	entries[1].Hash = recorder.ComputeHash(entries[1])
	var payload []byte
	for _, entry := range entries {
		raw, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload, raw...)
		payload = append(payload, '\n')
	}
	env := signedEnvelope(t, id, start, start+1, payload, priv)
	env.EventCount = 2
	env.Chain.EntryVersion = version
	env.Chain.SegmentHeadHash = entries[0].Hash
	env.Chain.SegmentTailHash = entries[1].Hash
	env.Chain.CheckpointHash = entries[1].Hash
	env.Chain.CheckpointSignature = conductor.SignaturePrefixEd25519 + sig
	env.Chain.FollowerRecorderPubHex = hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	if version == 3 {
		env.Chain.SessionID = session
		env.Chain.ChainKind = "proxy"
		env.Chain.WriterInstanceID = "writer-1"
	}
	env, err := auditbatcher.SignEnvelope(env, "audit-signer", priv)
	if err != nil {
		t.Fatal(err)
	}
	// Verify the fixture's recorder signature independently of the audit signature.
	if err := recorder.VerifyChain(entries, priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	return env, payload
}

func TestStoreSessionOverlapContract(t *testing.T) {
	for _, tc := range []struct {
		name, session string
		start         uint64
		version, want int
		unknown       string
	}{
		{name: "independent_v2", session: "second-run", version: 2, want: http.StatusAccepted},
		{name: "same_v2_fork", session: "first-run", version: 2, want: http.StatusConflict},
		{name: "out_of_order_nonoverlap", session: "first-run", start: 10, version: 2, want: http.StatusAccepted},
		{name: "same_v3_fork", session: "first-run", version: 3, want: http.StatusConflict},
		{name: "different_v3_namespace", session: "second-run", version: 3, want: http.StatusAccepted},
		{name: "unknown_old_row", session: "second-run", version: 2, want: http.StatusConflict, unknown: `{"old":"format"}`},
		{name: "malformed_old_row", session: "second-run", version: 2, want: http.StatusConflict, unknown: "{"},
		{name: "mixed_old_row", session: "second-run", version: 2, want: http.StatusConflict, unknown: "mixed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, _, priv := testHandler(t)
			first, payload := sessionEnvelope(t, priv, "session-first", "first-run", tc.start, tc.version)
			if tc.unknown != "" {
				if tc.unknown == "mixed" {
					payload = []byte(strings.Replace(string(payload), "first-run", "another-run", 1))
				} else {
					payload = []byte(tc.unknown)
				}
				sum := sha256.Sum256(payload)
				first.PayloadBytes = uint64(len(payload))
				first.PayloadSHA256 = hex.EncodeToString(sum[:])
				var err error
				first, err = auditbatcher.SignEnvelope(first, "audit-signer", priv)
				if err != nil {
					t.Fatal(err)
				}
			}
			if w := postBatch(t, handler, first, payload); w.Code != http.StatusAccepted {
				t.Fatalf("first=%d %s", w.Code, w.Body.String())
			}
			if w := postBatch(t, handler, first, payload); w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"status":"duplicate"`) {
				t.Fatalf("duplicate=%d %s", w.Code, w.Body.String())
			}
			second, payload2 := sessionEnvelope(t, priv, "session-second", tc.session, 0, tc.version)
			if w := postBatch(t, handler, second, payload2); w.Code != tc.want {
				t.Fatalf("second=%d %s want=%d", w.Code, w.Body.String(), tc.want)
			}
			second.BatchID = first.BatchID
			var err error
			second, err = auditbatcher.SignEnvelope(second, "audit-signer", priv)
			if err != nil {
				t.Fatal(err)
			}
			if w := postBatch(t, handler, second, payload2); w.Code != http.StatusConflict {
				t.Fatalf("batch-ID conflict=%d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestStoreLegacyHistoryReopen(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
	}{
		{"known", http.StatusAccepted},
		{"digest_mismatch", http.StatusConflict},
		{"oversize", http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, _, priv := testHandler(t)
			path := filepath.Join(t.TempDir(), "sink.db")
			store, err := OpenStore(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close() }()
			handler.store = store
			first, payload := sessionEnvelope(t, priv, "persisted-first", "first-run", 0, 2)
			if w := postBatch(t, handler, first, payload); w.Code != http.StatusAccepted {
				t.Fatalf("first=%d %s", w.Code, w.Body.String())
			}
			switch tc.name {
			case "digest_mismatch":
				_, err = store.db.ExecContext(t.Context(), `UPDATE audit_batches SET payload_blob = ?`, []byte("changed persisted payload"))
			case "oversize":
				_, err = store.db.ExecContext(t.Context(), `UPDATE audit_batches SET payload_blob = zeroblob(?)`, conductor.MaxAuditPayloadBytes+1)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = OpenStore(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			handler.store = store
			second, payload2 := sessionEnvelope(t, priv, "persisted-second", "second-run", 0, 2)
			if w := postBatch(t, handler, second, payload2); w.Code != tc.want {
				t.Fatalf("second=%d %s want=%d", w.Code, w.Body.String(), tc.want)
			}
		})
	}
}

// An incoming payload that cannot establish a session must never be exempted,
// even when the stored overlapping row has a known session.
func TestStoreUnknownIncomingNeverExempt(t *testing.T) {
	handler, _, priv := testHandler(t)
	first, payload := sessionEnvelope(t, priv, "unknown-incoming-first", "first-run", 0, 2)
	if w := postBatch(t, handler, first, payload); w.Code != http.StatusAccepted {
		t.Fatalf("first=%d %s", w.Code, w.Body.String())
	}
	second, _ := sessionEnvelope(t, priv, "unknown-incoming-second", "second-run", 0, 2)
	payload2 := []byte("{")
	sum := sha256.Sum256(payload2)
	second.PayloadBytes = uint64(len(payload2))
	second.PayloadSHA256 = hex.EncodeToString(sum[:])
	second, err := auditbatcher.SignEnvelope(second, "audit-signer", priv)
	if err != nil {
		t.Fatal(err)
	}
	if w := postBatch(t, handler, second, payload2); w.Code != http.StatusConflict {
		t.Fatalf("unknown incoming=%d %s", w.Code, w.Body.String())
	}
}

// With several distinct sessions stored for one range, a divergent history for
// any one of them is still a fork, whichever order the sessions arrived in.
func TestStoreForkAcrossSeveralSessions(t *testing.T) {
	for _, order := range [][]string{{"run-a", "run-b"}, {"run-b", "run-a"}} {
		handler, _, priv := testHandler(t)
		for _, session := range order {
			env, payload := sessionEnvelope(t, priv, "seed-"+session, session, 0, 2)
			if w := postBatch(t, handler, env, payload); w.Code != http.StatusAccepted {
				t.Fatalf("%v seed %s=%d %s", order, session, w.Code, w.Body.String())
			}
		}
		for _, tc := range []struct {
			id, session string
			start       uint64
			want        int
		}{
			{"fork-a", "run-a", 0, http.StatusConflict},
			{"fork-b", "run-b", 0, http.StatusConflict},
			{"fork-a-partial", "run-a", 1, http.StatusConflict},
			{"run-c", "run-c", 0, http.StatusAccepted},
			{"fork-c", "run-c", 0, http.StatusConflict},
		} {
			env, payload := sessionEnvelope(t, priv, tc.id, tc.session, tc.start, 2)
			if w := postBatch(t, handler, env, payload); w.Code != tc.want {
				t.Fatalf("%v %s=%d %s want=%d", order, tc.id, w.Code, w.Body.String(), tc.want)
			}
		}
	}
}

// cancelAtCheck reports cancellation from its nth context check onward.
type cancelAtCheck struct {
	context.Context
	n, checks int
}

func (c *cancelAtCheck) Err() error {
	c.checks++
	if c.checks >= c.n {
		return context.Canceled
	}
	return nil
}

// Cancellation at any context check inside the fork scan must surface as an
// error. Only a completed scan may return the fork or exemption verdict, so
// cancellation can never skip a stored candidate.
func TestStoreForkScanCancellationNeverSkips(t *testing.T) {
	handler, store, priv := testHandler(t)
	for _, session := range []string{"run-a", "run-b"} {
		env, payload := sessionEnvelope(t, priv, "seed-"+session, session, 0, 2)
		if w := postBatch(t, handler, env, payload); w.Code != http.StatusAccepted {
			t.Fatalf("seed %s=%d %s", session, w.Code, w.Body.String())
		}
	}
	for _, tc := range []struct {
		name, session string
		want          error
	}{
		{"same_session_fork", "run-a", ErrForkDetected},
		{"independent_run", "run-c", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, payload := sessionEnvelope(t, priv, "cancel-"+tc.name, tc.session, 0, 2)
			canceled, completed := false, false
			for n := 1; n < 100 && !completed; n++ {
				tx, err := store.db.BeginTx(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				_, err = detectFork(&cancelAtCheck{Context: context.Background(), n: n}, tx, env, payload)
				_ = tx.Rollback()
				switch {
				case errors.Is(err, context.Canceled):
					canceled = true
				case errors.Is(err, tc.want) || (err == nil && tc.want == nil):
					completed = true
				default:
					t.Fatalf("n=%d err=%v want %v or cancellation", n, err, tc.want)
				}
			}
			if !canceled || !completed {
				t.Fatalf("canceled=%v completed=%v", canceled, completed)
			}
		})
	}
}
