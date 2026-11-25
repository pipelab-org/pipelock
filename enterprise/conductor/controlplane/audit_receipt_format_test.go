//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestAuditIngestHandlerRefusesReceiptV3(t *testing.T) {
	path, _ := testreceipt.V3(t, t.TempDir(), false)
	v3Bytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenSQLiteAuditStore(t.Context(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	pub, priv := testAuditSigner(t)
	handler := newAuditIngestTestHandler(t, store, auditKeyResolverFor(pub), 0)

	for name, payload := range map[string][]byte{
		"direct":          v3Bytes,
		"leading-newline": append([]byte("\n"), v3Bytes...),
	} {
		t.Run(name, func(t *testing.T) {
			req := signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow)
			w := postAuditBatch(t, handler, req)
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusUnprocessableEntity, w.Body.String())
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			testreceipt.RequiresV3Refusal(t, errors.New(body.Error), "audit batch", "the fleet audit receiver")
		})
	}
}
