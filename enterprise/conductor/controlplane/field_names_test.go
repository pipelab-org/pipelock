//go:build enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

func TestRequestAndArtifactFieldNames(t *testing.T) {
	for _, tc := range []struct {
		body   string
		reject bool
	}{
		{`{"bundle":{"version":1}}`, false},
		{`{"Bundle":{"version":1}}`, false},
		{`{"bundle":{},"Bundle":{}}`, true},
		{`{"Bundle":{"Version":1}}`, true},
		{`{"Bundle":{"version":1,"Version":2}}`, true},
	} {
		var target struct {
			Bundle conductor.PolicyBundle `json:"bundle"`
		}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(tc.body))
		if err := decodeStrictJSON(httptest.NewRecorder(), r, 4096, &target); (err != nil) != tc.reject {
			t.Fatalf("reject=%v: %v", tc.reject, err)
		}
		if tc.reject && target.Bundle.Version != 0 {
			t.Fatal("rejected request populated target")
		}
	}
}

func TestSignedFollowerUploadFieldNames(t *testing.T) {
	for _, tc := range []struct {
		body   string
		dest   func() any
		reject bool
	}{
		{`{"envelope":{"batch_id":"a"}}`, func() any { return new(ingestAuditBatchRequest) }, false},
		{`{"Envelope":{"batch_id":"a"}}`, func() any { return new(ingestAuditBatchRequest) }, false},
		{`{"envelope":{"Batch_id":"a"}}`, func() any { return new(ingestAuditBatchRequest) }, true},
		{`{"envelope":{"applied_state":{"Active_bundle_id":"a"}}}`, func() any { return new(ingestAuditBatchRequest) }, true},
		{`{"heartbeat_id":"a"}`, func() any { return new(conductor.AppliedStateHeartbeat) }, false},
		{`{"Heartbeat_id":"a"}`, func() any { return new(conductor.AppliedStateHeartbeat) }, true},
		{`{"applied_state":{"Active_bundle_id":"a"}}`, func() any { return new(conductor.AppliedStateHeartbeat) }, true},
		{`{"status":{"Org_id":"a"}}`, func() any { return new(runtimeStatusRequest) }, false},
		{`{"status":{"org_id":"a","Org_id":"b"}}`, func() any { return new(runtimeStatusRequest) }, true},
	} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(tc.body))
		if err := decodeStrictJSON(httptest.NewRecorder(), r, 4096, tc.dest()); (err != nil) != tc.reject {
			t.Errorf("%s: reject=%v: %v", tc.body, tc.reject, err)
		}
	}
}
