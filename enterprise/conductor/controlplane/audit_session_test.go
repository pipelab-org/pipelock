//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const auditRunRecorderKeyID = "recorder-key-1"

type auditRunRunConfig struct {
	queue           *auditbatcher.Queue
	recorderDir     string
	auditPrivate    ed25519.PrivateKey
	recorderPrivate ed25519.PrivateKey
	fixedSession    string
}

type auditRunObservedRun struct {
	batch   auditbatcher.Batch
	session string
}

func auditRunProduceRun(t *testing.T, cfg auditRunRunConfig) auditRunObservedRun {
	t.Helper()
	identity := defaultFollowerIdentity()
	pub := cfg.recorderPrivate.Public().(ed25519.PublicKey)
	producer, err := auditbatcher.NewProducer(auditbatcher.ProducerConfig{
		Queue: cfg.queue, OrgID: identity.OrgID, FleetID: identity.FleetID, InstanceID: identity.InstanceID,
		AuditSignerKeyID: testAuditKeyID, RecorderKeyID: auditRunRecorderKeyID,
		AuditSigner: cfg.auditPrivate, RecorderPublicKey: pub, Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = producer.Close() })
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: cfg.recorderDir, CheckpointInterval: 2, SignCheckpoints: true}, nil, cfg.recorderPrivate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	session := cfg.fixedSession
	if session == "" {
		session, err = recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	} else {
		err = rec.AcquireSession(session)
	}
	if err != nil {
		t.Fatal(err)
	}
	rec.SetObserver(producer)
	for _, summary := range []string{"first captured event", "second captured event"} {
		if err := rec.Record(recorder.Entry{SessionID: session, Type: "capture", Transport: "fetch", Summary: summary, Detail: map[string]any{"summary": summary}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if err := producer.Close(); err != nil {
		t.Fatal(err)
	}
	lease, err := cfg.queue.Claim()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.queue.Release(lease.ID); err != nil {
		t.Fatal(err)
	}
	batch := lease.Batch
	if err := validateAuditBatchForIdentity(batch.Envelope, batch.Payload, identity, testNow, auditKeyResolverFor(cfg.auditPrivate.Public().(ed25519.PublicKey))); err != nil {
		t.Fatalf("real signed batch invalid: %v", err)
	}
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(batch.Payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.VerifyChain(entries, pub); err != nil {
		t.Fatalf("real signed recorder chain invalid: %v", err)
	}
	if len(entries) != 3 || batch.Envelope.SeqStart != 0 || batch.Envelope.SeqEnd != 2 || batch.Envelope.Chain.EntryVersion != recorder.CurrentWriteEntryVersion || batch.Envelope.Chain.SessionID != "" {
		t.Fatalf("unexpected real v2 segment: %+v entries=%d", batch.Envelope, len(entries))
	}
	for _, entry := range entries {
		if entry.SessionID != session {
			t.Fatalf("payload session mismatch: %q != %q", entry.SessionID, session)
		}
	}
	t.Logf("valid signed run session=%s v=%d seq=%d-%d envelope_session=%q batch=%s", session, batch.Envelope.Chain.EntryVersion, batch.Envelope.SeqStart, batch.Envelope.SeqEnd, batch.Envelope.Chain.SessionID, batch.Envelope.BatchID)
	return auditRunObservedRun{batch: batch, session: session}
}

type auditRunHandlerDoer struct {
	handler  http.Handler
	lastCode int
	lastBody string
}

func (d *auditRunHandlerDoer) Do(req *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	d.handler.ServeHTTP(w, req)
	d.lastCode, d.lastBody = w.Code, w.Body.String()
	return w.Result(), nil
}

func auditRunPost(t *testing.T, h *Handler, batch auditbatcher.Batch) *httptest.ResponseRecorder {
	t.Helper()
	return postAuditBatch(t, h, ingestAuditBatchRequest{Envelope: batch.Envelope, Payload: batch.Payload})
}

func TestAuditIndependentV2Runs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	auditPub, auditPrivate := testAuditSigner(t)
	_, recorderPrivate := testAuditSigner(t)
	keyring, err := auditbatcher.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	queueConfig := auditbatcher.Config{Dir: filepath.Join(root, "queue"), Keyring: keyring}
	q, err := auditbatcher.Open(queueConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	storePath := filepath.Join(root, "audit.db")
	store := openTestSQLiteAuditStore(t, storePath)
	t.Cleanup(func() { _ = store.Close() })
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(auditPub), 0)
	doer := &auditRunHandlerDoer{handler: handler}
	newTransport := func() *auditbatcher.Transport {
		tr, trErr := auditbatcher.NewTransport(auditbatcher.TransportConfig{BaseURL: "https://conductor.vendor.example", Client: doer, Queue: q})
		if trErr != nil {
			t.Fatal(trErr)
		}
		return tr
	}
	cfg := auditRunRunConfig{queue: q, recorderDir: filepath.Join(root, "recorder"), auditPrivate: auditPrivate, recorderPrivate: recorderPrivate}
	first := auditRunProduceRun(t, cfg)
	t.Run("first_run_accepted_and_acked", func(t *testing.T) {
		if err := newTransport().DeliverOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
		if doer.lastCode != http.StatusAccepted || !strings.Contains(doer.lastBody, `"status":"accepted"`) {
			t.Fatalf("first response=%d %s", doer.lastCode, doer.lastBody)
		}
		stats, err := q.Stats()
		if err != nil || stats != (auditbatcher.Stats{}) {
			t.Fatalf("first queue stats=%+v err=%v", stats, err)
		}
		t.Logf("first transport HTTP%d body=%s queue=%+v", doer.lastCode, doer.lastBody, stats)
	})
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	q, err = auditbatcher.Open(queueConfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.queue = q
	store = openTestSQLiteAuditStore(t, storePath)
	handler = newAuditIngestTestHandler(t, store, auditKeyResolverFor(auditPub), 0)
	doer.handler = handler
	t.Run("identical_retry_after_store_and_queue_reopen_is_duplicate", func(t *testing.T) {
		w := auditRunPost(t, handler, first.batch)
		if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"status":"duplicate"`) {
			t.Fatalf("duplicate response=%d %s", w.Code, w.Body.String())
		}
		t.Logf("duplicate HTTP%d body=%s", w.Code, w.Body.String())
	})
	second := auditRunProduceRun(t, cfg)
	if first.session == second.session || first.batch.Envelope.BatchID == second.batch.Envelope.BatchID {
		t.Fatal("fresh runs did not have distinct sessions and batches")
	}
	t.Run("fresh_run_should_be_accepted", func(t *testing.T) {
		w := auditRunPost(t, handler, second.batch)
		t.Logf("fresh run HTTP%d body=%s first_session=%s second_session=%s", w.Code, w.Body.String(), first.session, second.session)
		if w.Code != http.StatusAccepted {
			t.Errorf("valid independent signed v2 run got HTTP%d body=%s; want HTTP%d", w.Code, w.Body.String(), http.StatusAccepted)
		}
	})
	t.Run("genuine_same_session_divergent_history_remains_conflict", func(t *testing.T) {
		forkConfig := queueConfig
		forkConfig.Dir = filepath.Join(root, "fork-queue")
		forkQueue, err := auditbatcher.Open(forkConfig)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = forkQueue.Close() })
		forkRun := cfg
		forkRun.queue, forkRun.recorderDir, forkRun.fixedSession = forkQueue, filepath.Join(root, "fork-recorder"), first.session
		fork := auditRunProduceRun(t, forkRun)
		if bytes.Equal(first.batch.Payload, fork.batch.Payload) {
			t.Fatal("fork fixture did not diverge")
		}
		w := auditRunPost(t, handler, fork.batch)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), ErrAuditForkDetected.Error()) {
			t.Fatalf("genuine fork response=%d %s", w.Code, w.Body.String())
		}
		t.Logf("same-session fork HTTP%d body=%s", w.Code, w.Body.String())
	})
	t.Run("same_batch_id_different_valid_session_remains_conflict", func(t *testing.T) {
		changed := second.batch
		changed.Envelope.BatchID = first.batch.Envelope.BatchID
		changed.Envelope, err = auditbatcher.SignEnvelope(changed.Envelope, testAuditKeyID, auditPrivate)
		if err != nil {
			t.Fatal(err)
		}
		if w := auditRunPost(t, handler, changed); w.Code != http.StatusConflict {
			t.Fatalf("different-session ID reuse=%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("same_batch_id_changed_signed_envelope_remains_conflict", func(t *testing.T) {
		changed := first.batch
		changed.Envelope.EmittedAt = testNow.Add(time.Second)
		changed.Envelope, err = auditbatcher.SignEnvelope(changed.Envelope, testAuditKeyID, auditPrivate)
		if err != nil {
			t.Fatal(err)
		}
		w := auditRunPost(t, handler, changed)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), ErrAuditForkDetected.Error()) {
			t.Fatalf("batch-id conflict response=%d %s", w.Code, w.Body.String())
		}
		t.Logf("same-id changed canonical envelope HTTP%d body=%s", w.Code, w.Body.String())
	})
	t.Run("tampered_payload_fails_hash_binding", func(t *testing.T) {
		changed := first.batch
		changed.Payload = append(append([]byte(nil), changed.Payload...), byte(' '))
		w := auditRunPost(t, handler, changed)
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("tampered response=%d %s", w.Code, w.Body.String())
		}
		t.Logf("payload tampering HTTP%d body=%s", w.Code, w.Body.String())
	})
	t.Run("independent_run_transport_acked", func(t *testing.T) {
		if err := newTransport().DeliverOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
		if doer.lastCode != http.StatusAccepted {
			t.Fatalf("response=%d %s", doer.lastCode, doer.lastBody)
		}
		stats, err := q.Stats()
		if err != nil || stats != (auditbatcher.Stats{}) {
			t.Fatalf("queue=%+v err=%v", stats, err)
		}
	})
	t.Run("genuine_fork_quarantine_survives_reopen", func(t *testing.T) {
		forkRun := cfg
		forkRun.recorderDir, forkRun.fixedSession = filepath.Join(root, "quarantine-fork"), first.session
		auditRunProduceRun(t, forkRun)
		if err := newTransport().DeliverOnce(t.Context()); err == nil || doer.lastCode != http.StatusConflict {
			t.Fatalf("err=%v response=%d", err, doer.lastCode)
		}
		files, err := os.ReadDir(filepath.Join(queueConfig.Dir, "dead"))
		if err != nil || len(files) != 1 {
			t.Fatalf("files=%v err=%v", files, err)
		}
		path := filepath.Join(queueConfig.Dir, "dead", files[0].Name())
		before, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		if err := q.Close(); err != nil {
			t.Fatal(err)
		}
		q, err = auditbatcher.Open(queueConfig)
		if err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("quarantine bytes changed")
		}
		stats, err := q.Stats()
		if err != nil || stats != (auditbatcher.Stats{Dead: 1}) {
			t.Fatalf("queue=%+v err=%v", stats, err)
		}
		if _, err := q.Claim(); !errors.Is(err, auditbatcher.ErrQueueEmpty) {
			t.Fatalf("dead batch claim=%v", err)
		}
	})
}

func TestAuditLegacySessionConservativeHistory(t *testing.T) {
	root := t.TempDir()
	auditPub, auditPrivate := testAuditSigner(t)
	_, recorderPrivate := testAuditSigner(t)
	keyring, err := auditbatcher.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	queue, err := auditbatcher.Open(auditbatcher.Config{Dir: filepath.Join(root, "queue"), Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close() })
	cfg := auditRunRunConfig{queue: queue, recorderDir: filepath.Join(root, "recorder"), auditPrivate: auditPrivate, recorderPrivate: recorderPrivate}
	first := auditRunProduceRun(t, cfg)
	lease, err := queue.Claim()
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Ack(lease.ID); err != nil {
		t.Fatal(err)
	}
	second := auditRunProduceRun(t, cfg)
	for _, tc := range []struct {
		name     string
		mutate   func(*auditbatcher.Batch)
		oversize bool
	}{
		{name: "malformed", mutate: func(b *auditbatcher.Batch) { b.Payload = []byte("{") }},
		{name: "missing", mutate: func(b *auditbatcher.Batch) { b.Payload = []byte(`{"old":"format"}`) }},
		{name: "mixed_sessions", mutate: func(b *auditbatcher.Batch) {
			b.Payload = bytes.Replace(b.Payload, []byte(first.session), []byte("different-session"), 1)
		}},
		{name: "digest_mismatch"},
		{name: "oversize_persisted", oversize: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
			defer func() { _ = store.Close() }()
			handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(auditPub), 0)
			old := first.batch
			if tc.mutate != nil {
				tc.mutate(&old)
				sum := sha256.Sum256(old.Payload)
				old.Envelope.PayloadBytes = uint64(len(old.Payload))
				old.Envelope.PayloadSHA256 = hex.EncodeToString(sum[:])
				old.Envelope, err = auditbatcher.SignEnvelope(old.Envelope, testAuditKeyID, auditPrivate)
				if err != nil {
					t.Fatal(err)
				}
			}
			if w := auditRunPost(t, handler, old); w.Code != http.StatusAccepted {
				t.Fatalf("initial=%d %s", w.Code, w.Body.String())
			}
			if tc.name == "digest_mismatch" {
				if _, err := store.db.ExecContext(t.Context(), `UPDATE audit_batches SET payload_blob = ?`, []byte("changed persisted payload")); err != nil {
					t.Fatal(err)
				}
			}
			if tc.oversize {
				if _, err := store.db.ExecContext(t.Context(), `UPDATE audit_batches SET payload_blob = zeroblob(?)`, conductor.MaxAuditPayloadBytes+1); err != nil {
					t.Fatal(err)
				}
			}
			if w := auditRunPost(t, handler, second.batch); w.Code != http.StatusConflict {
				t.Fatalf("unknown history=%d %s", w.Code, w.Body.String())
			}
		})
	}
	t.Run("stale_signed_replay", func(t *testing.T) {
		store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
		defer func() { _ = store.Close() }()
		handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(auditPub), 0)
		stale := first.batch
		stale.Envelope.EmittedAt = testNow.Add(-2 * conductor.DefaultAuditMaxSkew)
		stale.Envelope, err = auditbatcher.SignEnvelope(stale.Envelope, testAuditKeyID, auditPrivate)
		if err != nil {
			t.Fatal(err)
		}
		if w := auditRunPost(t, handler, stale); w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("stale replay=%d %s", w.Code, w.Body.String())
		}
	})
}

func controlplaneSessionBatch(t *testing.T, priv ed25519.PrivateKey, id, session string, start uint64, version int) auditbatcher.Batch {
	t.Helper()
	entries := []recorder.Entry{
		{Version: version, Sequence: start, Timestamp: testNow, SessionID: session, Type: "capture", Summary: id, PrevHash: recorder.GenesisHash},
		{Version: version, Sequence: start + 1, Timestamp: testNow, SessionID: session, Type: "checkpoint"},
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
	env := signedAcceptedAuditBatch(t, defaultFollowerIdentity(), id, start, start+1, payload, testNow).Envelope
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
	env, err := auditbatcher.SignEnvelope(env, testAuditKeyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Verify the fixture's recorder signature independently of the audit signature.
	if err := recorder.VerifyChain(entries, priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	return auditbatcher.Batch{Envelope: env, Payload: payload}
}

func TestConductorAuditSequenceContract(t *testing.T) {
	for _, tc := range []struct {
		name, session   string
		start           uint64
		version, want   int
		unknownIncoming bool
	}{
		{name: "out_of_order_nonoverlap", session: "first-run", start: 10, version: 2, want: http.StatusAccepted},
		{name: "same_v3_fork", session: "first-run", version: 3, want: http.StatusConflict},
		{name: "different_v3_namespace", session: "second-run", version: 3, want: http.StatusAccepted},
		{name: "unknown_incoming", session: "second-run", version: 2, want: http.StatusConflict, unknownIncoming: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := testAuditSigner(t)
			store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
			defer func() { _ = store.Close() }()
			handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
			first := controlplaneSessionBatch(t, priv, "first-batch", "first-run", tc.start, tc.version)
			if w := auditRunPost(t, handler, first); w.Code != http.StatusAccepted {
				t.Fatalf("first=%d %s", w.Code, w.Body.String())
			}
			second := controlplaneSessionBatch(t, priv, "second-batch", tc.session, 0, tc.version)
			if tc.unknownIncoming {
				second.Payload = []byte("{")
				sum := sha256.Sum256(second.Payload)
				second.Envelope.PayloadBytes = uint64(len(second.Payload))
				second.Envelope.PayloadSHA256 = hex.EncodeToString(sum[:])
				var err error
				second.Envelope, err = auditbatcher.SignEnvelope(second.Envelope, testAuditKeyID, priv)
				if err != nil {
					t.Fatal(err)
				}
			}
			if w := auditRunPost(t, handler, second); w.Code != tc.want {
				t.Fatalf("second=%d %s want=%d", w.Code, w.Body.String(), tc.want)
			}
		})
	}
}

// Change only the checkpoint's session claim, whose v2 hash binds that claim.
// Its signature covers PrevHash, so the existing checkpoint signature remains
// valid. Rebind all affected endpoints and sign the new audit envelope.
func mixedSessionAuditBatch(t *testing.T, batch auditbatcher.Batch, priv ed25519.PrivateKey) auditbatcher.Batch {
	t.Helper()
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(batch.Payload))
	if err != nil {
		t.Fatal(err)
	}
	last := len(entries) - 1
	entries[last].SessionID = entries[0].SessionID + "-other-session"
	entries[last].Hash = recorder.ComputeHash(entries[last])
	var payload []byte
	for _, entry := range entries {
		raw, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload, raw...)
		payload = append(payload, '\n')
	}
	batch.Payload = payload
	batch.Envelope.Chain.SegmentHeadHash = entries[0].Hash
	batch.Envelope.Chain.SegmentTailHash = entries[last].Hash
	batch.Envelope.Chain.CheckpointHash = entries[last].Hash
	sum := sha256.Sum256(payload)
	batch.Envelope.PayloadSHA256 = hex.EncodeToString(sum[:])
	batch.Envelope.PayloadBytes = uint64(len(payload))
	batch.Envelope, err = auditbatcher.SignEnvelope(batch.Envelope, testAuditKeyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := recorder.ReadEntriesFromReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if parsed[0].SessionID == parsed[last].SessionID {
		t.Fatal("fixture is not mixed-session")
	}
	if err := recorder.VerifyChain(parsed, priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("mixed fixture chain/checkpoint invalid: %v", err)
	}
	if err := conductor.ValidateAuditSegment(batch.Envelope.Chain, parsed); err != nil {
		t.Fatalf("mixed fixture segment invalid: %v", err)
	}
	if err := validateAuditBatchForIdentity(batch.Envelope, payload, defaultFollowerIdentity(), testNow, auditKeyResolverFor(priv.Public().(ed25519.PublicKey))); err != nil {
		t.Fatalf("mixed fixture signature/digest invalid: %v", err)
	}
	return batch
}

func TestAuditMixedV2SessionValidChainRemainsConflict(t *testing.T) {
	for _, tc := range []struct {
		name          string
		mixedExisting bool
	}{{"persisted_mixed_session", true}, {"incoming_mixed_session", false}} {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := testAuditSigner(t)
			store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
			defer func() { _ = store.Close() }()
			handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
			first := controlplaneSessionBatch(t, priv, "mixed-history-first", "old-run", 0, 2)
			second := controlplaneSessionBatch(t, priv, "mixed-history-second", "new-run", 0, 2)
			if tc.mixedExisting {
				first = mixedSessionAuditBatch(t, first, priv)
			} else {
				second = mixedSessionAuditBatch(t, second, priv)
			}
			if w := auditRunPost(t, handler, first); w.Code != http.StatusAccepted {
				t.Fatalf("first=%d %s", w.Code, w.Body.String())
			}
			if w := auditRunPost(t, handler, second); w.Code != http.StatusConflict {
				t.Fatalf("MIXED_SESSION_EXEMPTION: response=%d %s; want409", w.Code, w.Body.String())
			}
		})
	}
}

// With several distinct sessions stored for one range, a divergent history for
// any one of them is still a fork, whichever order the sessions arrived in.
func TestAuditForkAcrossSeveralSessions(t *testing.T) {
	for _, order := range [][]string{{"run-a", "run-b"}, {"run-b", "run-a"}} {
		pub, priv := testAuditSigner(t)
		store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
		handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
		for _, session := range order {
			if w := auditRunPost(t, handler, controlplaneSessionBatch(t, priv, "seed-"+session, session, 0, 2)); w.Code != http.StatusAccepted {
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
			if w := auditRunPost(t, handler, controlplaneSessionBatch(t, priv, tc.id, tc.session, tc.start, 2)); w.Code != tc.want {
				t.Fatalf("%v %s=%d %s want=%d", order, tc.id, w.Code, w.Body.String(), tc.want)
			}
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// The exemption adds no way around signer enrolment, payload binding or the
// follower audience: each of those refusals still precedes the fork scan.
func TestAuditIndependentRunStillNeedsEnrolledSignerAndBinding(t *testing.T) {
	pub, priv := testAuditSigner(t)
	_, other := testAuditSigner(t)
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
	if w := auditRunPost(t, handler, controlplaneSessionBatch(t, priv, "enrolled-first", "run-a", 0, 2)); w.Code != http.StatusAccepted {
		t.Fatalf("first=%d %s", w.Code, w.Body.String())
	}
	if w := auditRunPost(t, handler, controlplaneSessionBatch(t, other, "unenrolled", "run-b", 0, 2)); w.Code != http.StatusUnauthorized {
		t.Fatalf("unenrolled signer=%d %s", w.Code, w.Body.String())
	}
	spliced := controlplaneSessionBatch(t, priv, "spliced", "run-b", 0, 2)
	spliced.Payload = controlplaneSessionBatch(t, priv, "other-payload", "run-c", 0, 2).Payload
	if w := auditRunPost(t, handler, spliced); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("payload splice=%d %s", w.Code, w.Body.String())
	}
	retargeted := controlplaneSessionBatch(t, priv, "retargeted", "run-b", 0, 2)
	retargeted.Envelope.InstanceID = "another-instance"
	var err error
	retargeted.Envelope, err = auditbatcher.SignEnvelope(retargeted.Envelope, testAuditKeyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	if w := auditRunPost(t, handler, retargeted); w.Code != http.StatusForbidden {
		t.Fatalf("cross-follower=%d %s", w.Code, w.Body.String())
	}
}

// auditCancelAtCheck reports cancellation from its nth context check onward.
type auditCancelAtCheck struct {
	context.Context
	n, checks int
}

func (c *auditCancelAtCheck) Err() error {
	c.checks++
	if c.checks >= c.n {
		return context.Canceled
	}
	return nil
}

// Cancellation at any context check inside the fork scan must surface as an
// error. Only a completed scan may return the fork or exemption verdict, so
// cancellation can never skip a stored candidate.
func TestAuditForkScanCancellationNeverSkips(t *testing.T) {
	pub, priv := testAuditSigner(t)
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)
	for _, session := range []string{"run-a", "run-b"} {
		if w := auditRunPost(t, handler, controlplaneSessionBatch(t, priv, "seed-"+session, session, 0, 2)); w.Code != http.StatusAccepted {
			t.Fatalf("seed %s=%d %s", session, w.Code, w.Body.String())
		}
	}
	for _, tc := range []struct {
		name, session string
		want          error
	}{
		{"same_session_fork", "run-a", ErrAuditForkDetected},
		{"independent_run", "run-c", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch := controlplaneSessionBatch(t, priv, "cancel-"+tc.name, tc.session, 0, 2)
			canceled, completed := false, false
			for n := 1; n < 100 && !completed; n++ {
				tx, err := store.db.BeginTx(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				_, err = detectAuditFork(&auditCancelAtCheck{Context: context.Background(), n: n}, tx, batch.Envelope, batch.Payload)
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
