// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testJevKey is built at runtime so it is not a credential-shaped literal.
var testJevKey = strings.Join([]string{"test", "jev", "key", "value"}, "-")

type jevServer struct {
	srv      *httptest.Server
	requests atomic.Int32
	lastBody atomic.Value
	lastAuth atomic.Value
	lastHdr  atomic.Value
}

func newJevServer(t *testing.T, handler func(w http.ResponseWriter)) (*jevServer, *x509.CertPool) {
	t.Helper()
	js := &jevServer{}
	js.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		js.requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		js.lastBody.Store(body)
		js.lastAuth.Store(r.Header.Get("Authorization"))
		js.lastHdr.Store(r.Header.Clone())
		handler(w)
	}))
	t.Cleanup(js.srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(js.srv.Certificate())
	return js, pool
}

func jevAnswer(body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
}

func newTestJev(t *testing.T, js *jevServer, pool *x509.CertPool, key string) *Jev {
	t.Helper()
	j, err := NewJev(JevOptions{Endpoint: js.srv.URL + "/v1/systemone", APIKey: key, Model: "jev-1.14.0", Threshold: 0.8, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestJevClassification(t *testing.T) {
	for _, tt := range []struct {
		name   string
		body   string
		status int
		state  State
		reason Reason
	}{
		{"below", `{"model":"jev-1.14.0","answers":{"redirects_agent":{"noul":0.1}}}`, 200, StateBenign, ""},
		{"equal_threshold", `{"answers":{"redirects_agent":{"noul":0.8}}}`, 200, StateFinding, ""},
		{"above", `{"answers":{"redirects_agent":{"noul":0.99}}}`, 200, StateFinding, ""},
		{"model_absent_ok", `{"answers":{"redirects_agent":{"noul":0}}}`, 200, StateBenign, ""},
		{"model_mismatch", `{"model":"jev-1.15.0","answers":{"redirects_agent":{"noul":0.1}}}`, 200, StateNotAssessed, ReasonStaleRevision},
		{"duplicate_score", `{"answers":{"redirects_agent":{"noul":0.99,"noul":0.1}}}`, 200, StateNotAssessed, ReasonMalformed},
		{"aliased_score", `{"answers":{"redirects_agent":{"noul":0.99,"NOUL":0.1}}}`, 200, StateNotAssessed, ReasonMalformed},
		{"duplicate_model", `{"model":"stale","model":"jev-1.14.0","answers":{"redirects_agent":{"noul":0.1}}}`, 200, StateNotAssessed, ReasonMalformed},
		{"missing_answer", `{"answers":{}}`, 200, StateNotAssessed, ReasonMalformed},
		{"string_score", `{"answers":{"redirects_agent":{"noul":"0.1"}}}`, 200, StateNotAssessed, ReasonMalformed},
		{"negative", `{"answers":{"redirects_agent":{"noul":-0.1}}}`, 200, StateNotAssessed, ReasonMalformed},
		{"above_one", `{"answers":{"redirects_agent":{"noul":1.5}}}`, 200, StateNotAssessed, ReasonMalformed},
		{"null_score", `{"answers":{"redirects_agent":{"noul":null}}}`, 200, StateNotAssessed, ReasonMalformed},
		{"trailing", `{"answers":{"redirects_agent":{"noul":0.1}}} {}`, 200, StateNotAssessed, ReasonMalformed},
		{"not_json", `ok`, 200, StateNotAssessed, ReasonMalformed},
		{"rate_limited", `{}`, 429, StateNotAssessed, ReasonUnavailable},
		{"overloaded", `{}`, 529, StateNotAssessed, ReasonUnavailable},
		{"server_error", `{}`, 500, StateNotAssessed, ReasonUnavailable},
		{"redirect", `{}`, 307, StateNotAssessed, ReasonRedirect},
		{"wrong_answer_type", `{"answers":{"redirects_agent":{"type":"choice","noul":0.1}}}`, 200, StateNotAssessed, ReasonMalformed},
		{"noul_answer_type", `{"answers":{"redirects_agent":{"type":"noul","noul":0.1}}}`, 200, StateBenign, ""},
		{"usage_metadata", `{"model":"jev-1.14.0","answers":{"redirects_agent":{"type":"noul","noul":0.1}},"usage":{"input_tokens":469,"output_tokens":23}}`, 200, StateBenign, ""},
		{"unknown_top_field", `{"answers":{"redirects_agent":{"type":"noul","noul":0.1}},"unexpected":true}`, 200, StateNotAssessed, ReasonMalformed},
		{"unknown_answer_field", `{"answers":{"redirects_agent":{"type":"noul","noul":0.1,"unexpected":true}}}`, 200, StateNotAssessed, ReasonMalformed},
		{"unknown_question", `{"answers":{"redirects_agent":{"type":"noul","noul":0.1},"other":{"type":"noul","noul":0.9}}}`, 200, StateNotAssessed, ReasonMalformed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			js, pool := newJevServer(t, func(w http.ResponseWriter) {
				w.Header().Set("Location", "https://api.vendor.example/elsewhere")
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			})
			got := newTestJev(t, js, pool, testJevKey).Check(t.Context(), testItem(), testPolicy())
			if got.State != tt.state || got.Reason != tt.reason {
				t.Fatalf("assessment = %+v, want %s/%s", got, tt.state, tt.reason)
			}
			if got.State == StateBenign || got.State == StateFinding {
				if got.Status != StatusAssessed || got.Score == nil {
					t.Fatalf("assessed result lacks status or score: %+v", got)
				}
			}
		})
	}
}

func TestJevRequestShape(t *testing.T) {
	js, pool := newJevServer(t, jevAnswer(`{"answers":{"redirects_agent":{"noul":0.1}}}`))
	if got := newTestJev(t, js, pool, testJevKey).Check(t.Context(), testItem(), testPolicy()); got.State != StateBenign {
		t.Fatalf("assessment: %+v", got)
	}
	if auth, _ := js.lastAuth.Load().(string); auth != "Bearer "+testJevKey {
		t.Fatal("authorization header missing or wrong")
	}
	hdr, _ := js.lastHdr.Load().(http.Header)
	for name := range hdr {
		if strings.Contains(strings.ToLower(name), "long-context") {
			t.Fatalf("long-context header sent: %s", name)
		}
	}
	var req struct {
		Model string `json:"model"`
		State struct {
			Surface   string    `json:"surface"`
			Untrusted []jevPart `json:"untrusted_content"`
		} `json:"state"`
		Questions map[string]jevQuestionSpec `json:"questions"`
	}
	body, _ := js.lastBody.Load().([]byte)
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	item := testItem()
	q := req.Questions[jevQuestionID]
	if req.Model != "jev-1.14.0" || req.State.Surface != item.Surface || len(req.State.Untrusted) != len(item.Parts) ||
		len(req.Questions) != 1 || q.Type != "noul" || q.Instructions != jevQuestion ||
		q.Criteria["true"] != jevCriteriaT || q.Criteria["false"] != jevCriteriaF {
		t.Fatalf("request shape: %s", body)
	}
	if req.State.Untrusted[0].Text != item.Parts[0].Text {
		t.Fatal("part text not forwarded")
	}
}

func TestJevFailsClosed(t *testing.T) {
	t.Run("empty_key_no_request", func(t *testing.T) {
		js, pool := newJevServer(t, jevAnswer(`{"answers":{"redirects_agent":{"noul":0.1}}}`))
		got := newTestJev(t, js, pool, "").Check(t.Context(), testItem(), testPolicy())
		if got.State != StateNotAssessed || got.Reason != ReasonUnavailable || js.requests.Load() != 0 {
			t.Fatalf("assessment=%+v requests=%d", got, js.requests.Load())
		}
	})
	t.Run("off_and_zero_policy", func(t *testing.T) {
		js, pool := newJevServer(t, jevAnswer(`{}`))
		j := newTestJev(t, js, pool, testJevKey)
		off := testPolicy()
		off.Mode = ModeOff
		for _, p := range []Policy{off, {}} {
			if got := j.Check(t.Context(), testItem(), p); got.State != StateOff {
				t.Fatalf("assessment: %+v", got)
			}
		}
		if js.requests.Load() != 0 {
			t.Fatal("off policy sent a request")
		}
	})
	t.Run("partial_benign_is_incomplete", func(t *testing.T) {
		js, pool := newJevServer(t, jevAnswer(`{"answers":{"redirects_agent":{"noul":0.1}}}`))
		item := testItem()
		item.Completeness = &Completeness{Status: Partial, Reason: ReasonTruncated}
		if got := newTestJev(t, js, pool, testJevKey).Check(t.Context(), item, testPolicy()); got.State != StateIncomplete {
			t.Fatalf("assessment: %+v", got)
		}
	})
	t.Run("partial_finding_stays", func(t *testing.T) {
		js, pool := newJevServer(t, jevAnswer(`{"answers":{"redirects_agent":{"noul":0.95}}}`))
		item := testItem()
		item.Completeness = &Completeness{Status: Partial, Reason: ReasonTruncated}
		if got := newTestJev(t, js, pool, testJevKey).Check(t.Context(), item, testPolicy()); got.State != StateFinding {
			t.Fatalf("assessment: %+v", got)
		}
	})
	t.Run("oversized_response", func(t *testing.T) {
		js, pool := newJevServer(t, jevAnswer(fmt.Sprintf(`{"answers":{"redirects_agent":{"noul":0.1}},"pad":%q}`, strings.Repeat("x", 4096))))
		p := testPolicy()
		p.MaxResponseBytes = 256
		if got := newTestJev(t, js, pool, testJevKey).Check(t.Context(), testItem(), p); got.State != StateNotAssessed || got.Reason != ReasonTooLarge {
			t.Fatalf("assessment: %+v", got)
		}
	})
	t.Run("request_over_budget", func(t *testing.T) {
		js, pool := newJevServer(t, jevAnswer(`{}`))
		p := testPolicy()
		p.MaxRequestBytes = 64
		if got := newTestJev(t, js, pool, testJevKey).Check(t.Context(), testItem(), p); got.Reason != ReasonOverBudget || js.requests.Load() != 0 {
			t.Fatalf("assessment=%+v requests=%d", got, js.requests.Load())
		}
	})
	t.Run("submitted_bytes_over_budget_no_request", func(t *testing.T) {
		js, pool := newJevServer(t, jevAnswer(`{}`))
		p := testPolicy()
		p.MaxRequestBytes = testItem().SubmittedBytes - 1
		got := newTestJev(t, js, pool, testJevKey).Check(t.Context(), testItem(), p)
		if got.State != StateIncomplete || got.Status != StatusNotChecked || got.Reason != ReasonOverBudget || js.requests.Load() != 0 {
			t.Fatalf("assessment=%+v requests=%d", got, js.requests.Load())
		}
	})
	t.Run("producer_over_budget_no_request", func(t *testing.T) {
		// The producer stopped on the budget: the item may carry no parts at
		// all, and that must read as an incomplete assessment, not as a
		// malformed item.
		js, pool := newJevServer(t, jevAnswer(`{}`))
		j := newTestJev(t, js, pool, testJevKey)
		for name, mutate := range map[string]func(*Item){
			"with_parts": func(*Item) {},
			"no_parts":   func(i *Item) { i.Parts, i.SubmittedBytes = nil, 0 },
		} {
			item := testItem()
			item.Completeness = &Completeness{Status: Partial, Reason: ReasonOverBudget}
			mutate(&item)
			got := j.Check(t.Context(), item, testPolicy())
			if got.State != StateIncomplete || got.Status != StatusNotChecked || got.Reason != ReasonOverBudget {
				t.Fatalf("%s: %+v", name, got)
			}
		}
		if js.requests.Load() != 0 {
			t.Fatalf("over-budget item sent %d requests", js.requests.Load())
		}
	})
	t.Run("producer_canceled_no_parts_no_request", func(t *testing.T) {
		js, pool := newJevServer(t, jevAnswer(`{}`))
		item := testItem()
		item.Completeness = &Completeness{Status: Partial, Reason: ReasonCanceled}
		item.Parts, item.SubmittedBytes = nil, 0
		got := newTestJev(t, js, pool, testJevKey).Check(t.Context(), item, testPolicy())
		if got.State != StateNotAssessed || got.Status != StatusNotChecked || got.Reason != ReasonCanceled {
			t.Fatalf("canceled build: %+v", got)
		}
		if js.requests.Load() != 0 {
			t.Fatalf("canceled build sent %d requests", js.requests.Load())
		}
	})
	// A canceled build that kept parts is still sent, and its finding stands.
	t.Run("producer_canceled_with_parts_is_sent", func(t *testing.T) {
		js, pool := newJevServer(t, jevAnswer(`{"answers":{"redirects_agent":{"noul":0.99}}}`))
		item := testItem()
		item.Completeness = &Completeness{Status: Partial, Reason: ReasonCanceled}
		got := newTestJev(t, js, pool, testJevKey).Check(t.Context(), item, testPolicy())
		if got.State != StateFinding || js.requests.Load() != 1 {
			t.Fatalf("canceled build with parts: %+v requests=%d", got, js.requests.Load())
		}
	})
	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		js, pool := newJevServer(t, func(http.ResponseWriter) { <-release })
		// Registered after the server, so it runs first and frees the handler
		// before the server's Close waits for it.
		t.Cleanup(func() { close(release) })
		p := testPolicy()
		p.Timeout = 100 * time.Millisecond
		if got := newTestJev(t, js, pool, testJevKey).Check(t.Context(), testItem(), p); got.State != StateNotAssessed || got.Reason != ReasonTimeout {
			t.Fatalf("assessment: %+v", got)
		}
	})
	t.Run("invalid_policy_and_item", func(t *testing.T) {
		js, pool := newJevServer(t, jevAnswer(`{}`))
		j := newTestJev(t, js, pool, testJevKey)
		for name, mutate := range map[string]func(*Policy){
			"unknown_mode":     func(p *Policy) { p.Mode = "maybe" },
			"zero_timeout":     func(p *Policy) { p.Timeout = 0 },
			"zero_request":     func(p *Policy) { p.MaxRequestBytes = 0 },
			"zero_response":    func(p *Policy) { p.MaxResponseBytes = 0 },
			"max_response_cap": func(p *Policy) { p.MaxResponseBytes = math.MaxInt64 },
		} {
			p := testPolicy()
			mutate(&p)
			if got := j.Check(t.Context(), testItem(), p); got.Status != StatusInvalid || got.Reason != ReasonPolicy {
				t.Fatalf("%s: %+v", name, got)
			}
		}
		empty := testItem()
		empty.Parts = nil
		empty.SubmittedBytes = 0
		if got := j.Check(t.Context(), empty, testPolicy()); got.Status != StatusInvalid || got.Reason != ReasonMalformed {
			t.Fatalf("empty item: %+v", got)
		}
		if js.requests.Load() != 0 {
			t.Fatalf("invalid input sent %d requests", js.requests.Load())
		}
	})
	t.Run("unsupported_kind", func(t *testing.T) {
		js, pool := newJevServer(t, jevAnswer(`{}`))
		item := testItem()
		item.Kind = KindAction
		if got := newTestJev(t, js, pool, testJevKey).Check(t.Context(), item, testPolicy()); got.Reason != ReasonUnsupported || js.requests.Load() != 0 {
			t.Fatalf("assessment: %+v", got)
		}
	})
}

func TestNewJevOptions(t *testing.T) {
	for _, opts := range []JevOptions{
		{Endpoint: "https://api.vendor.example/v1", Model: "", Threshold: 0.5},
		{Endpoint: "https://api.vendor.example/v1", Model: "m", Threshold: 0},
		{Endpoint: "https://api.vendor.example/v1", Model: "m", Threshold: 1.5},
		{Endpoint: "http://api.vendor.example/v1", Model: "m", Threshold: 0.5},
	} {
		if _, err := NewJev(opts); err == nil {
			t.Fatalf("accepted invalid options: %+v", opts)
		}
	}
	// The key never appears in an error, even an option error.
	_, err := NewJev(JevOptions{Endpoint: "https://api.vendor.example/v1?x=1", APIKey: testJevKey, Model: "m", Threshold: 0.5})
	if err == nil || strings.Contains(err.Error(), testJevKey) {
		t.Fatalf("err = %v", err)
	}
}
