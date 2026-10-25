//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Exercise the complete Start/Shutdown ordering with the real recorder,
// producer, encrypted queue and transport. The incomplete checkpoint span
// cannot be uploaded until cleanup closes the recorder.
func TestServerShutdownDrainsFinalAuditBatch(t *testing.T) {
	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := auditbatcher.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	queueConfig := auditbatcher.Config{Dir: filepath.Join(t.TempDir(), "queue"), Keyring: keyring}
	q, err := auditbatcher.Open(queueConfig)
	if err != nil {
		t.Fatal(err)
	}
	s.conductorAuditQueue = q
	p, err := auditbatcher.NewProducer(auditbatcher.ProducerConfig{
		Queue: q, OrgID: "test-org", FleetID: "test-fleet", InstanceID: "test-instance",
		AuditSignerKeyID: "test-audit", RecorderKeyID: "test-recorder", AuditSigner: priv, RecorderPublicKey: pub,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.conductorProducer = p
	r, err := recorder.New(recorder.Config{
		Enabled: true, Dir: filepath.Join(t.TempDir(), "recorder"), SignCheckpoints: true,
	}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	s.recorder = r
	r.SetObserver(p)
	if err := r.Record(recorder.Entry{SessionID: "test-session", Type: "test", Summary: "final span"}); err != nil {
		t.Fatal(err)
	}
	// Apply the Conductor's envelope admission (structure, payload hash and the
	// 60-second freshness window) so an acceptance means the shutdown upload would
	// be admitted in production, not only that it reached the endpoint. Signature
	// verification needs the fleet roster and is out of scope here.
	var uploads, admitted atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploads.Add(1)
		var upload struct {
			Envelope conductor.AuditBatchEnvelope `json:"envelope"`
			Payload  []byte                       `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&upload); err != nil ||
			upload.Envelope.ValidateForConductorWithPayload(time.Now(), conductor.DefaultAuditMaxSkew, upload.Payload) != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		admitted.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	transport, err := auditbatcher.NewTransport(auditbatcher.TransportConfig{
		Queue: q, BaseURL: upstream.URL, Client: upstream.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.conductorAudit = transport
	result := make(chan error, 1)
	go func() { result <- s.Start(t.Context()) }()
	select {
	case <-s.startupNotified():
	case err := <-result:
		t.Fatalf("Start returned before readiness: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not become ready")
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * serverShutdownTimeout):
		t.Fatal("Start did not finish shutdown")
	}
	if got, ok := uploads.Load(), admitted.Load(); got != 1 || ok != 1 {
		t.Errorf("final audit uploads = %d, admitted = %d, want 1 and 1", got, ok)
	}
	reopened, err := auditbatcher.Open(queueConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	stats, err := reopened.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats != (auditbatcher.Stats{}) {
		t.Errorf("queue after shutdown/reopen = %+v, want empty", stats)
	}
}
