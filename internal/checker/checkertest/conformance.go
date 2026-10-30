// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package checkertest supplies reusable wire conformance tests for checker clients.
package checkertest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
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

// Run exercises success, typed failures, malformed wire replies, transport
// refusals, and local disabled/unsupported behavior. Every request the
// implementation sends is validated against the wire contract, and request IDs
// must never repeat across the run. It does not evaluate detection accuracy.
func Run(t *testing.T, factory Factory) {
	t.Helper()
	type testCase struct {
		name   string
		change func(*checker.Response)
		raw    func(string) string
		// serve replaces the protocol mock; target is a second server that
		// fails the test if a redirect is ever followed to it.
		serve  func(w http.ResponseWriter, r *http.Request, target string)
		item   func(*checker.Item)
		policy func(*checker.Policy)
		noCall bool
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
	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		cases = append(cases, testCase{name: fmt.Sprintf("redirect_%d", code), serve: func(w http.ResponseWriter, r *http.Request, target string) {
			http.Redirect(w, r, target, code)
		}, want: checker.StateNotAssessed, status: checker.StatusNotChecked})
	}
	for _, code := range []int{http.StatusNoContent, http.StatusServiceUnavailable} {
		cases = append(cases, testCase{name: fmt.Sprintf("http_%d", code), serve: func(w http.ResponseWriter, _ *http.Request, _ string) {
			w.WriteHeader(code)
		}, want: checker.StateNotAssessed, status: checker.StatusNotChecked})
	}
	cases = append(cases,
		testCase{name: "oversized", serve: func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = io.WriteString(w, strings.Repeat(" ", int(Policy().MaxResponseBytes)+1))
		}, want: checker.StateNotAssessed, status: checker.StatusInvalid},
		// An endless body must be cut off at the response budget, not read
		// until the deadline: a client that buffers it reports a timeout.
		testCase{name: "endless_body", serve: func(w http.ResponseWriter, r *http.Request, _ string) {
			chunk := []byte(strings.Repeat(" ", 1024))
			stop := time.After(10 * time.Second)
			for {
				select {
				case <-r.Context().Done():
					return
				case <-stop:
					return
				default:
				}
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		}, want: checker.StateNotAssessed, status: checker.StatusInvalid},
		testCase{name: "off", policy: func(p *checker.Policy) { p.Mode = checker.ModeOff }, noCall: true, want: checker.StateOff},
	)
	for _, kind := range []checker.Kind{checker.KindAction, checker.KindImage, "unknown"} {
		cases = append(cases, testCase{
			name: "kind_" + string(kind), item: func(i *checker.Item) { i.Kind = kind },
			noCall: true, want: checker.StateNotAssessed, status: checker.StatusNotChecked,
		})
	}
	var ids sync.Map
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("redirect followed")
			}))
			defer target.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if tc.serve != nil {
					tc.serve(w, r, target.URL)
					return
				}
				if err := serveResponse(w, r, &ids, tc.change, tc.raw); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()
			item, policy := Item(), Policy()
			if tc.item != nil {
				tc.item(&item)
			}
			if tc.policy != nil {
				tc.policy(&policy)
			}
			got := factory(t, srv.URL).Check(t.Context(), item, policy)
			if got.State != tc.want || got.Status != tc.status {
				t.Errorf("got state=%s status=%s reason=%s; want state=%s status=%s", got.State, got.Status, got.Reason, tc.want, tc.status)
			}
			want := int32(1)
			if tc.noCall {
				want = 0
			}
			if calls.Load() != want {
				t.Errorf("requests = %d, want %d", calls.Load(), want)
			}
		})
	}
}

// checkRequest enforces the request half of the wire contract, so a client
// that computes the binding over different bytes, alters the item, reuses a
// request ID or ignores the request budget fails before any reply is served.
func checkRequest(r *http.Request, ids *sync.Map) (checker.Request, error) {
	var req checker.Request
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Method != http.MethodPost || mediaType != "application/json" {
		return req, errors.New("request is not a JSON POST")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, Policy().MaxRequestBytes+1))
	if err != nil {
		return req, err
	}
	if int64(len(body)) > Policy().MaxRequestBytes {
		return req, errors.New("request exceeds the policy request budget")
	}
	if err := jsonscan.DecodeStrict(body, &req); err != nil {
		return req, fmt.Errorf("request schema: %w", err)
	}
	var item checker.Item
	if err := jsonscan.DecodeStrict(req.Item, &item); err != nil {
		return req, fmt.Errorf("item schema: %w", err)
	}
	switch {
	case req.Version != checker.Version:
		return req, errors.New("wrong request protocol_version")
	case req.ID == "":
		return req, errors.New("missing request_id")
	case req.PolicyGeneration != Policy().Generation:
		return req, errors.New("wrong policy_generation")
	case req.InputBinding != checker.Binding(req.Item):
		return req, errors.New("input_binding is not SHA-256 of the exact item bytes")
	case !reflect.DeepEqual(item, Item()):
		return req, errors.New("item changed in transit")
	}
	if _, seen := ids.LoadOrStore(req.ID, true); seen {
		return req, errors.New("request_id reused")
	}
	return req, nil
}

func serveResponse(w http.ResponseWriter, r *http.Request, ids *sync.Map, change func(*checker.Response), raw func(string) string) error {
	req, err := checkRequest(r, ids)
	if err != nil {
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
