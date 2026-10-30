// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package checkertest supplies reusable wire conformance tests for checker clients.
package checkertest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/checker"
)

// Item returns a fresh fixture, including a labelled decoded view and untrusted
// tool context. Fixture bytes are synthetic and carry no operator intent.
func Item() checker.Item {
	return checker.Item{
		ID: "item-1", Kind: checker.KindText, Surface: "tool_result",
		Transport: "mcp_stdio", Direction: "response", ExtractionVersion: "text/v1",
		OriginalBytes: 5, SubmittedBytes: 10,
		Completeness: &checker.Completeness{Status: checker.Complete},
		Parts: []checker.Part{
			{ID: "raw", Role: "content", Representation: "original", Text: "hello"},
			{ID: "view", Role: "decoded_view", Representation: "base64/v1", Text: "hello"},
		},
		Context: []checker.ContextValue{{Name: "tool", Value: "example", Origin: checker.OriginToolOutput, Trust: checker.TrustUntrusted}},
	}
}

// Policy returns explicit test budgets and a synthetic pinned revision and scale.
func Policy() checker.Policy {
	return checker.Policy{
		Mode: checker.ModeBlock, Generation: "policy-1", Timeout: time.Second,
		MaxRequestBytes: 16384, MaxResponseBytes: 4096,
		Revision: checker.Revision{Checker: "example/v1", Model: "example-model/v1", Adapter: "example-adapter/v1"},
		Scale:    &checker.Scale{Name: "example-risk", CalibrationID: "example-calibration/v1", Min: 0, Max: 1},
	}
}

// Response echoes the request identity and binding with a complete benign result.
func Response(req checker.Request) checker.Response {
	var item checker.Item
	_ = json.Unmarshal(req.Item, &item)
	return checker.Response{
		Version: checker.Version, RequestID: req.ID, ItemID: item.ID,
		InputBinding: req.InputBinding, Revision: Policy().Revision,
		Completeness: &checker.Completeness{Status: checker.Complete},
		Status:       checker.StatusAssessed, Classification: checker.Benign,
	}
}

// Factory builds the implementation under test for a loopback mock endpoint.
// The harness supplies the resolved Policy to each Check call.
type Factory func(t *testing.T, endpoint string) checker.Checker

// Run exercises success, typed failures, malformed wire replies, and local
// disabled/unsupported behavior. It does not evaluate detection accuracy.
func Run(t *testing.T, factory Factory) {
	t.Helper()
	type testCase struct {
		name   string
		change func(*checker.Response)
		raw    func(string) string
		want   checker.State
		status checker.Status
	}
	cases := []testCase{
		{name: "benign", want: checker.StateBenign, status: checker.StatusAssessed},
		{name: "suspicious", change: func(r *checker.Response) {
			r.Classification = checker.Suspicious
			r.Findings = []checker.Finding{{ReasonID: "instruction_override", PartIDs: []string{"view"}}}
		}, want: checker.StateFinding, status: checker.StatusAssessed},
		{name: "abstain", change: func(r *checker.Response) { r.Classification = checker.Abstain }, want: checker.StateIncomplete, status: checker.StatusAssessed},
		{name: "partial", change: func(r *checker.Response) {
			r.Completeness = &checker.Completeness{Status: checker.Partial, Reason: checker.ReasonTruncated}
		}, want: checker.StateIncomplete, status: checker.StatusAssessed},
		{name: "score", change: func(r *checker.Response) {
			v := 0.5
			r.Score = &checker.Score{Value: &v, Scale: Policy().Scale.Name, CalibrationID: Policy().Scale.CalibrationID}
		}, want: checker.StateBenign, status: checker.StatusAssessed},
	}
	for _, reason := range []checker.Reason{
		checker.ReasonUnavailable, checker.ReasonTimeout, checker.ReasonCanceled,
		checker.ReasonRefused, checker.ReasonUnsupported, checker.ReasonOverBudget, checker.ReasonTruncated,
		checker.ReasonMalformed, checker.ReasonStaleRevision,
	} {
		state := checker.StateNotAssessed
		if reason == checker.ReasonTruncated {
			state = checker.StateIncomplete
		}
		cases = append(cases, testCase{name: "not_checked_" + string(reason), change: func(r *checker.Response) {
			r.Status, r.Classification, r.Reason = checker.StatusNotChecked, "", reason
		}, want: state, status: checker.StatusNotChecked})
	}
	invalid := map[string]func(*checker.Response){
		"version":                func(r *checker.Response) { r.Version = "unknown" },
		"request_identity":       func(r *checker.Response) { r.RequestID = "wrong" },
		"item_identity":          func(r *checker.Response) { r.ItemID = "wrong" },
		"missing_item":           func(r *checker.Response) { r.ItemID = "" },
		"binding":                func(r *checker.Response) { r.InputBinding = "wrong" },
		"revision":               func(r *checker.Response) { r.Revision.Model = "wrong" },
		"missing_completeness":   func(r *checker.Response) { r.Completeness = nil },
		"bad_completeness":       func(r *checker.Response) { r.Completeness.Status = "unknown" },
		"unknown_status":         func(r *checker.Response) { r.Status = "unknown" },
		"unknown_classification": func(r *checker.Response) { r.Classification = "unknown" },
		"not_checked_benign":     func(r *checker.Response) { r.Status, r.Reason = checker.StatusNotChecked, checker.ReasonUnavailable },
		"not_checked_reason": func(r *checker.Response) {
			r.Status, r.Classification, r.Reason = checker.StatusNotChecked, "", "unknown"
		},
		"assessed_reason":   func(r *checker.Response) { r.Reason = checker.ReasonRefused },
		"benign_finding":    func(r *checker.Response) { r.Findings = []checker.Finding{{ReasonID: "unexpected"}} },
		"missing_reason_id": func(r *checker.Response) { r.Classification = checker.Suspicious; r.Findings = []checker.Finding{{}} },
		"unknown_part": func(r *checker.Response) {
			r.Classification = checker.Suspicious
			r.Findings = []checker.Finding{{ReasonID: "example", PartIDs: []string{"absent"}}}
		},
	}
	for name, change := range invalid {
		cases = append(cases, testCase{name: name, change: change, want: checker.StateNotAssessed, status: checker.StatusInvalid})
	}
	for name, raw := range map[string]func(string) string{
		"duplicate_keys": func(s string) string {
			return strings.Replace(s, `"classification":"benign"`, `"classification":"suspicious","classification":"benign"`, 1)
		},
		"escaped_duplicate": func(s string) string {
			return strings.Replace(s, `"classification":"benign"`, `"classificati\u006fn":"suspicious","classification":"benign"`, 1)
		},
		"nested_duplicate": func(s string) string {
			return strings.Replace(s, `"completeness":{"status":"complete"}`, `"completeness":{"status":"partial","status":"complete"}`, 1)
		},
		"missing_completeness_field": func(s string) string { return strings.Replace(s, `"completeness":{"status":"complete"},`, ``, 1) },
		"duplicate_item": func(s string) string {
			return strings.Replace(s, `"item_id":"item-1"`, `"item_id":"item-1","item_id":"item-1"`, 1)
		},
		"trailing_json": func(s string) string { return s + `{}` },
		"trailing_junk": func(s string) string { return s + `!` },
		"unknown_field": func(s string) string { return strings.Replace(s, `{`, `{"advice":"execute",`, 1) },
		"case_alias":    func(s string) string { return strings.Replace(s, `"status"`, `"Status"`, 1) },
		"null":          func(string) string { return `null` },
		"empty":         func(string) string { return `` },
		"array":         func(s string) string { return `[` + s + `,` + s + `]` },
		"invalid_utf8":  func(s string) string { return strings.Replace(s, "benign", string([]byte{0xff}), 1) },
	} {
		cases = append(cases, testCase{name: name, raw: raw, want: checker.StateNotAssessed, status: checker.StatusInvalid})
	}
	for _, value := range []string{"NaN", "Inf", "-Inf", "Infinity", "-Infinity", "1e999", "-0.1", "1.1", "null", `"0.5"`} {
		cases = append(cases, testCase{name: "score_" + value, raw: func(s string) string {
			return strings.TrimSuffix(s, "}") + `,"score":{"value":` + value + `,"scale":"example-risk","calibration_id":"example-calibration/v1"}}`
		}, want: checker.StateNotAssessed, status: checker.StatusInvalid})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if err := serveResponse(w, r, tc.change, tc.raw); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()
			got := factory(t, srv.URL).Check(t.Context(), Item(), Policy())
			if got.State != tc.want || got.Status != tc.status {
				t.Errorf("got state=%s status=%s reason=%s; want state=%s status=%s", got.State, got.Status, got.Reason, tc.want, tc.status)
			}
			if calls.Load() != 1 {
				t.Errorf("requests = %d, want 1", calls.Load())
			}
		})
	}
}

func serveResponse(w http.ResponseWriter, r *http.Request, change func(*checker.Response), raw func(string) string) error {
	var req checker.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	response := Response(req)
	if change != nil {
		change(&response)
	}
	data, _ := json.Marshal(response)
	body := string(data)
	if raw != nil {
		body = raw(body)
	}
	_, _ = io.WriteString(w, body)
	return nil
}
