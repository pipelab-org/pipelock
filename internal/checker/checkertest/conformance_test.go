// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package checkertest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker"
)

func TestHarness(t *testing.T) {
	Run(t, func(t *testing.T, endpoint string) checker.Checker {
		t.Helper()
		client, err := checker.NewClient(checker.Options{Endpoint: endpoint, AllowLoopbackHTTP: true})
		if err != nil {
			t.Fatal(err)
		}
		return client
	})
}

func TestMalformedMockRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/check", strings.NewReader("{"))
	r.Header.Set("Content-Type", "application/json")
	if err := serveResponse(w, r, &sync.Map{}, nil, nil); err == nil || w.Code != http.StatusBadRequest {
		t.Fatalf("err=%v status=%d", err, w.Code)
	}
}

// TestRequestChecks proves the mock rejects each request-side contract
// violation, so a broken client cannot pass Run by echoing what it sent.
func TestRequestChecks(t *testing.T) {
	valid := func() map[string]any {
		data, _ := json.Marshal(Item())
		return map[string]any{
			"protocol_version": checker.Version, "request_id": "request-1", "policy_generation": Policy().Generation,
			"input_binding": checker.Binding(data), "item": json.RawMessage(data),
		}
	}
	send := func(ids *sync.Map, method, contentType, body string) error {
		r := httptest.NewRequestWithContext(t.Context(), method, "/check", strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		_, err := checkRequest(r, ids)
		return err
	}
	encode := func(v map[string]any) string { data, _ := json.Marshal(v); return string(data) }

	ids := &sync.Map{}
	if err := send(ids, http.MethodPost, "application/json; charset=utf-8", encode(valid())); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if err := send(ids, http.MethodPost, "application/json", encode(valid())); err == nil {
		t.Fatal("reused request_id accepted")
	}
	changedItem := Item()
	changedItem.Parts[1].Text = "other"
	changedData, _ := json.Marshal(changedItem)
	for name, change := range map[string]func(map[string]any){
		"version":    func(v map[string]any) { v["protocol_version"] = "unknown" },
		"missing_id": func(v map[string]any) { v["request_id"] = "" },
		"generation": func(v map[string]any) { v["policy_generation"] = "other" },
		"binding":    func(v map[string]any) { v["input_binding"] = checker.Binding([]byte("{}")) },
		"unknown":    func(v map[string]any) { v["advice"] = "x" },
		"bad_item":   func(v map[string]any) { v["item"] = json.RawMessage(`{"item_id":"item-1","extra":1}`) },
		"changed_item": func(v map[string]any) {
			v["item"], v["input_binding"] = json.RawMessage(changedData), checker.Binding(changedData)
		},
		"oversized": func(v map[string]any) {
			v["request_id"] = strings.Repeat("x", int(Policy().MaxRequestBytes))
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := valid()
			v["request_id"] = "request-" + name
			change(v)
			if err := send(&sync.Map{}, http.MethodPost, "application/json", encode(v)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if err := send(&sync.Map{}, http.MethodGet, "application/json", encode(valid())); err == nil {
		t.Fatal("GET accepted")
	}
	if err := send(&sync.Map{}, http.MethodPost, "text/plain", encode(valid())); err == nil {
		t.Fatal("non-JSON content type accepted")
	}
}
