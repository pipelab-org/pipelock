//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestFleetSinkRefusesReceiptV3(t *testing.T) {
	path, _ := testreceipt.V3(t, t.TempDir(), false)
	v3Bytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	handler, _, priv := testHandler(t)
	for name, payload := range map[string][]byte{
		"direct":          v3Bytes,
		"leading-newline": append([]byte("\n"), v3Bytes...),
	} {
		t.Run(name, func(t *testing.T) {
			env := signedEnvelope(t, "batch-"+name, 1, 1, payload, priv)
			resp := postBatch(t, handler, env, payload)
			if resp.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want %d; body=%s", resp.Code, http.StatusUnprocessableEntity, resp.Body.String())
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			testreceipt.RequiresV3Refusal(t, errors.New(body.Error), "audit batch", "the fleet audit receiver")
		})
	}
}
