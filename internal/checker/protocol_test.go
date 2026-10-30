// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"testing"
	"time"
)

func wireRequest(item Item) Request {
	data, _ := json.Marshal(item)
	return Request{Version: Version, ID: "request", PolicyGeneration: testPolicy().Generation, InputBinding: Binding(data), Item: data}
}

func TestItemValidation(t *testing.T) {
	for name, change := range map[string]func(*Item){
		"payload":    func(i *Item) { i.Payload = json.RawMessage(`{}`) },
		"label_utf8": func(i *Item) { i.Surface = string([]byte{0xff}) },
		"id":         func(i *Item) { i.ID = "" }, "surface": func(i *Item) { i.Surface = "" }, "transport": func(i *Item) { i.Transport = "" },
		"direction": func(i *Item) { i.Direction = "" }, "extraction": func(i *Item) { i.ExtractionVersion = "" },
		"original_bytes": func(i *Item) { i.OriginalBytes = -1 }, "submitted_bytes": func(i *Item) { i.SubmittedBytes++ },
		"parts": func(i *Item) { i.Parts = nil }, "part_id": func(i *Item) { i.Parts[0].ID = "" },
		"duplicate_part": func(i *Item) { i.Parts = append(i.Parts, i.Parts[0]) }, "role": func(i *Item) { i.Parts[0].Role = "" },
		"representation": func(i *Item) { i.Parts[0].Representation = "" }, "utf8": func(i *Item) { i.Parts[0].Text = string([]byte{0xff}) },
		"completeness": func(i *Item) { i.Completeness = nil }, "completeness_reason": func(i *Item) { i.Completeness.Reason = ReasonTruncated },
		"partial_reason": func(i *Item) { i.Completeness = &Completeness{Status: Partial} },
		"context_name":   func(i *Item) { i.Context = []ContextValue{{Origin: OriginToolOutput, Trust: TrustUntrusted}} },
		"context_origin": func(i *Item) { i.Context = []ContextValue{{Name: "tool", Trust: TrustUntrusted}} },
		"context_trust": func(i *Item) {
			i.Context = []ContextValue{{Name: "task", Origin: OriginToolOutput, Trust: TrustAuthenticated}}
		},
		"context_unknown_trust": func(i *Item) { i.Context = []ContextValue{{Name: "task", Origin: OriginOperator, Trust: "unknown"}} },
		"context_utf8": func(i *Item) {
			i.Context = []ContextValue{{Name: "task", Origin: OriginOperator, Trust: TrustAuthenticated, Value: string([]byte{0xff})}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			item := testItem()
			change(&item)
			if validItem(item) {
				t.Fatalf("accepted %s", name)
			}
		})
	}
	item := testItem()
	item.Context = []ContextValue{{Name: "task", Origin: OriginOperator, Trust: TrustAuthenticated, Value: "example"}}
	if !validItem(item) {
		t.Fatal("authenticated operator rejected")
	}
}

func TestResponseBindingsAndPartial(t *testing.T) {
	item, p := testItem(), testPolicy()
	req := wireRequest(item)
	data, _ := json.Marshal(testResponse(req))
	for name, change := range map[string]func(*Request, *Item, *Policy){
		"invalid_policy":  func(_ *Request, _ *Item, p *Policy) { p.Mode = "" },
		"invalid_item":    func(_ *Request, i *Item, _ *Policy) { i.ID = "" },
		"version":         func(r *Request, _ *Item, _ *Policy) { r.Version = "unknown" },
		"request_id":      func(r *Request, _ *Item, _ *Policy) { r.ID = "" },
		"generation":      func(r *Request, _ *Item, _ *Policy) { r.PolicyGeneration = "wrong" },
		"binding":         func(r *Request, _ *Item, _ *Policy) { r.InputBinding = "wrong" },
		"different_item":  func(_ *Request, i *Item, _ *Policy) { i.Surface = "different" },
		"response_budget": func(_ *Request, _ *Item, p *Policy) { p.MaxResponseBytes = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			r, i, policy := req, item, p
			change(&r, &i, &policy)
			if got := DecodeResponse(data, r, i, policy); got.Status != StatusInvalid {
				t.Fatal(got)
			}
		})
	}
	unsupported := item
	unsupported.Kind = KindAction
	if got := DecodeResponse(data, req, unsupported, p); got.Reason != ReasonUnsupported {
		t.Fatal(got)
	}
	item.Completeness = &Completeness{Status: Partial, Reason: ReasonTruncated}
	req = wireRequest(item)
	data, _ = json.Marshal(testResponse(req))
	if got := DecodeResponse(data, req, item, p); got.State != StateIncomplete {
		t.Fatal(got)
	}
}

func TestScoreAndFindings(t *testing.T) {
	item, p := testItem(), testPolicy()
	req := wireRequest(item)
	value := 0.5
	p.Scale = &Scale{Name: "scale", CalibrationID: "calibration", Min: 0, Max: 1}
	for name, change := range map[string]func(*Response, *Policy){
		"no_scale":          func(_ *Response, p *Policy) { p.Scale = nil },
		"wrong_scale":       func(r *Response, _ *Policy) { r.Score.Scale = "other" },
		"wrong_calibration": func(r *Response, _ *Policy) { r.Score.CalibrationID = "other" },
		"no_value":          func(r *Response, _ *Policy) { r.Score.Value = nil },
		"not_checked_score": func(r *Response, _ *Policy) {
			r.Status = StatusNotChecked
			r.Classification = ""
			r.Reason = ReasonUnavailable
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := testResponse(req)
			response.Score = &Score{Value: &value, Scale: p.Scale.Name, CalibrationID: p.Scale.CalibrationID}
			policy := p
			change(&response, &policy)
			data, _ := json.Marshal(response)
			if got := DecodeResponse(data, req, item, policy); got.Status != StatusInvalid {
				t.Fatal(got)
			}
		})
	}
	for _, v := range []float64{0, 1} {
		r := testResponse(req)
		r.Score = &Score{Value: &v, Scale: p.Scale.Name, CalibrationID: p.Scale.CalibrationID}
		data, _ := json.Marshal(r)
		if got := DecodeResponse(data, req, item, p); got.State != StateBenign {
			t.Fatal(got)
		}
	}
	for _, v := range []float64{math.Inf(-1), math.NaN()} {
		r := testResponse(req)
		r.Score = &Score{Value: &v, Scale: p.Scale.Name, CalibrationID: p.Scale.CalibrationID}
		if validResult(r, item, p.Scale) {
			t.Fatal("nonfinite accepted")
		}
	}
}

type checkerFunc func(context.Context, Item, Policy) Assessment

func (f checkerFunc) Check(ctx context.Context, i Item, p Policy) Assessment { return f(ctx, i, p) }

func TestSelfTest(t *testing.T) {
	benign, suspicious := testItem(), testItem()
	suspicious.ID = "suspicious"
	client := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		response := testResponse(req)
		if response.ItemID == suspicious.ID {
			response.Classification = Suspicious
		}
		_ = json.NewEncoder(w).Encode(response)
	})
	if err := SelfTest(t.Context(), client, testPolicy(), benign, suspicious); err != nil {
		t.Fatal(err)
	}
	alwaysBenign := clientFor(t, goodHandler(t))
	err := SelfTest(t.Context(), alwaysBenign, testPolicy(), benign, suspicious)
	var failure *HealthError
	if !errors.As(err, &failure) || failure.Probe != Suspicious || failure.Error() != "checker known-answer self-test failed" {
		t.Fatalf("%v", err)
	}
	p := testPolicy()
	p.Mode = ModeOff
	if err = SelfTest(t.Context(), client, p, benign, suspicious); !errors.As(err, &failure) || failure.Probe != Benign {
		t.Fatal(err)
	}
	var first time.Time
	calls := 0
	fake := checkerFunc(func(ctx context.Context, i Item, _ Policy) Assessment {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("no deadline")
		}
		calls++
		if calls == 1 {
			first = deadline
		} else if deadline != first {
			t.Error("deadline reset")
		}
		state := StateBenign
		if i.ID == suspicious.ID {
			state = StateFinding
		}
		return Assessment{State: state, Status: StatusAssessed}
	})
	if err = SelfTest(t.Context(), fake, testPolicy(), benign, suspicious); err != nil {
		t.Fatal(err)
	}
	calls = 0
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = SelfTest(ctx, fake, testPolicy(), benign, suspicious); !errors.As(err, &failure) {
		t.Fatal(err)
	}
}
