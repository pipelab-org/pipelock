// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestExactRequestExceptions(t *testing.T) {
	body := `{"sendInvitation":false,"roles":["read"],"recipients":[{"email":"person@vendor.example"}]}`
	digest := sha256.Sum256([]byte(body))
	approved := config.RequestPolicyExactRequest{
		URL: "https://api.service.example.com/items/1/invite", Method: http.MethodPost,
		BodySHA256: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Owner: "operator", Reason: "approved access setup",
	}
	rule := exactExceptionRule()
	rule.Route.PathPatterns = []string{`/items/.+/invite$`}
	rule.Except = &config.RequestPolicyException{Requests: []config.RequestPolicyExactRequest{approved}}
	m, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	base := RequestMeta{
		Host: "api.service.example.com", Method: http.MethodPost, Path: "/items/1/invite",
		JSONBodyParsed: true, JSONBody: jsonBody(t, body), ExactURL: approved.URL, JSONBodySHA256: approved.BodySHA256,
	}
	for _, tc := range []struct {
		name string
		edit func(*RequestMeta)
		want string
	}{
		{"exact", func(*RequestMeta) {}, ""},
		{"changed payload", func(r *RequestMeta) { r.JSONBodySHA256 = strings.Repeat("0", 64) }, config.ActionBlock},
		{"sibling resource", func(r *RequestMeta) {
			r.Path = "/items/2/invite"
			r.ExactURL = "https://api.service.example.com/items/2/invite"
		}, config.ActionBlock},
		{"query", func(r *RequestMeta) { r.ExactURL += "?sendInvitation=true" }, config.ActionBlock},
		{"foreign destination", func(r *RequestMeta) { r.ExactURL = "https://other.example/items/1/invite" }, config.ActionBlock},
		{"missing URL", func(r *RequestMeta) { r.ExactURL = "" }, config.ActionBlock},
		{"missing digest", func(r *RequestMeta) { r.JSONBodySHA256 = "" }, config.ActionBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.edit(&r)
			if got := m.Evaluate(r).Action; got != tc.want {
				t.Fatalf("action=%q want=%q", got, tc.want)
			}
		})
	}
	if !m.NeedsExactRequest(base) {
		t.Fatal("exact route not selected")
	}
	other := base
	other.Path = "/other"
	if m.NeedsExactRequest(other) {
		t.Fatal("unrelated route selected")
	}
	if (*Matcher)(nil).NeedsExactRequest(base) {
		t.Fatal("nil matcher selected")
	}
	batchCfg := &config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule}, Batch: []config.RequestPolicyBatch{{Route: config.RequestPolicyRoute{PathPatterns: []string{`/\$batch$`}}, RequestsField: "requests", MethodField: "method", URLField: "url", BodyField: "body", MaxSubRequests: 4}}}
	batchMatcher, err := NewMatcher(batchCfg)
	if err != nil {
		t.Fatal(err)
	}
	batchMeta := base
	batchMeta.Path = "/$batch"
	batchBody := []byte(`{"requests":[{"method":"POST","url":"/items/1/invite","body":` + body + `}]}`)
	if got, ok := batchMatcher.EvaluateBatch(batchMeta, batchBody); !ok || got.Action != config.ActionBlock {
		t.Fatalf("batch=%+v parsed=%v", got, ok)
	}
	blocking := rule
	blocking.Name = "independent-block"
	blocking.Except = nil
	combined, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule, blocking}})
	if err != nil {
		t.Fatal(err)
	}
	if got := combined.Evaluate(base).Action; got != config.ActionBlock {
		t.Fatalf("approval overrode independent rule: %q", got)
	}
	for _, action := range []string{config.ActionWarn, config.ActionAllow} {
		if got := m.EvaluateUninspectable(base, action, PredAnyBody).Action; got != config.ActionBlock {
			t.Fatalf("uninspectable action=%q", got)
		}
	}
	for _, bad := range []config.RequestPolicyExactRequest{
		{URL: approved.URL},
	} {
		rule.Except.Requests = []config.RequestPolicyExactRequest{bad}
		if _, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule}}); err == nil {
			t.Fatal("invalid approval accepted")
		}
	}
	rule.Except.Requests = []config.RequestPolicyExactRequest{approved}
	rule.Except.Requests[0].ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	m, err = NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Evaluate(base).Action; got != config.ActionBlock {
		t.Fatalf("expired approval action=%q", got)
	}
	rule.Except.Field = "action"
	if _, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule}}); err == nil {
		t.Fatal("mixed exception accepted")
	}
}

func TestExactRequestMethodOverride(t *testing.T) {
	if HasMethodOverride(nil) {
		t.Fatal("nil headers have override")
	}
	for _, name := range methodOverrideHeaders {
		h := make(http.Header)
		h.Set(name, "")
		if !HasMethodOverride(h) {
			t.Fatalf("missed %s", name)
		}
	}
}

func TestCompileExactRequestRejectsInvalidEntries(t *testing.T) {
	approval := config.RequestPolicyExactRequest{URL: "https://api.vendor.example/items/1/invite", Method: http.MethodPost, BodySHA256: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	for _, tc := range []struct {
		name string
		edit func(*config.RequestPolicyExactRequest)
	}{
		{"invalid expiry", func(r *config.RequestPolicyExactRequest) { r.ExpiresAt = "invalid" }},
		{"invalid URL", func(r *config.RequestPolicyExactRequest) { r.URL = "https://%" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := approval
			tc.edit(&candidate)
			compiled := compileExactException(&config.RequestPolicyException{Requests: []config.RequestPolicyExactRequest{candidate}})
			if len(compiled.requests) != 0 {
				t.Fatal("invalid approval compiled")
			}
			if compiled.matches(RequestMeta{JSONBodyParsed: true, JSONBody: map[string]any{}, ExactURL: approval.URL, JSONBodySHA256: approval.BodySHA256, Method: approval.Method}) {
				t.Fatal("invalid approval granted relief")
			}
		})
	}
}

func TestExactRequestExpiresAfterMatcherConstruction(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(time.Hour)
	approval := config.RequestPolicyExactRequest{
		URL: "https://api.service.example.com/items/1/invite", Method: http.MethodPost,
		BodySHA256: strings.Repeat("a", 64), ExpiresAt: expires.Format(time.RFC3339),
		Owner: "operator", Reason: "approved request",
	}
	rule := exactExceptionRule()
	rule.Route.PathPatterns = []string{`/items/.+/invite$`}
	rule.Except = &config.RequestPolicyException{Requests: []config.RequestPolicyExactRequest{approval}}
	m, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	m.rules[0].except.now = func() time.Time { return now }
	meta := RequestMeta{Host: "api.service.example.com", Method: http.MethodPost, Path: "/items/1/invite", JSONBodyParsed: true, JSONBody: map[string]any{}, ExactURL: approval.URL, JSONBodySHA256: approval.BodySHA256}
	if got := m.Evaluate(meta).Action; got != "" {
		t.Fatalf("before expiry: %q", got)
	}
	now = expires
	if got := m.Evaluate(meta).Action; got != config.ActionBlock {
		t.Fatalf("at expiry, same matcher: %q", got)
	}
	now = expires.Add(time.Second)
	if got := m.Evaluate(meta).Action; got != config.ActionBlock {
		t.Fatalf("after expiry, same matcher: %q", got)
	}
}
