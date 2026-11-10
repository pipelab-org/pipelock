// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

// requestDerivedCanary is a query key long enough to clear the entropy floor.
// It is built at runtime so the source does not contain a credential-shaped literal.
func requestDerivedCanary() string {
	return strings.Join([]string{"Ab3kQ9mZ", "2xL7pW4n", "R8vT1cY6"}, "")
}

func TestBlockReasonOmitsRequestDerivedQueryKey(t *testing.T) {
	canary := requestDerivedCanary()
	cfg := testConfig()
	cfg.DLP.Patterns = nil
	s := MustNew(cfg)
	t.Cleanup(s.Close)

	t.Run("query key", func(t *testing.T) {
		raw := "https://api.vendor.example/v1?page=1&" + canary + "=1"
		got := s.Scan(context.Background(), raw)
		if got.Allowed {
			t.Fatal("high-entropy query key was allowed")
		}
		if strings.Contains(got.Reason, canary) {
			t.Fatalf("reason echoes the query key: %q", got.Reason)
		}
		if !strings.HasPrefix(got.Reason, queryEntropyKeyReasonPrefix+"at position 2 ") {
			t.Fatalf("reason = %q", got.Reason)
		}
		if !IsQueryEntropyResult(got) {
			t.Fatalf("IsQueryEntropyResult(%q) = false", got.Reason)
		}
		hint := OperatorHintForResult(got.Scanner, got.Reason)
		if !strings.Contains(hint, "query_entropy_exclusions") {
			t.Fatalf("key finding hint = %q", hint)
		}
	})

	t.Run("semicolon query key", func(t *testing.T) {
		raw := "https://api.vendor.example/v1?page=1;" + canary + "=1"
		got := s.Scan(context.Background(), raw)
		if got.Allowed {
			t.Fatal("high-entropy query key was allowed")
		}
		if strings.Contains(got.Reason, canary) {
			t.Fatalf("reason echoes the query key: %q", got.Reason)
		}
		if !strings.HasPrefix(got.Reason, queryEntropyKeyReasonPrefix+"at position 2 ") {
			t.Fatalf("reason = %q", got.Reason)
		}
	})

	t.Run("query param", func(t *testing.T) {
		const key = "callback"
		raw := "https://api.vendor.example/v1?" + key + "=" + canary
		got := s.Scan(context.Background(), raw)
		if got.Allowed {
			t.Fatal("high-entropy query value was allowed")
		}
		if strings.Contains(got.Reason, key) || strings.Contains(got.Reason, canary) {
			t.Fatalf("reason echoes request text: %q", got.Reason)
		}
		if !strings.HasPrefix(got.Reason, queryEntropyParamReasonPrefix+"at position 1 ") {
			t.Fatalf("reason = %q", got.Reason)
		}
		hint := OperatorHintForResult(got.Scanner, got.Reason)
		if !strings.Contains(hint, "query_entropy_param_exclusions") {
			t.Fatalf("param finding hint = %q", hint)
		}
	})

	t.Run("nested parameter", func(t *testing.T) {
		nestedCfg := testConfig()
		nestedCfg.DLP.Patterns = nil
		nestedCfg.FetchProxy.Monitoring.QueryEntropyExclusions = []string{"api.vendor.example"}
		nested := MustNew(nestedCfg)
		t.Cleanup(nested.Close)
		raw := "https://api.vendor.example/v1?" + canary + "=" + url.QueryEscape("http://169.254.169.254/latest")
		got := nested.Scan(context.Background(), raw)
		if got.Allowed {
			t.Fatal("nested metadata destination was allowed")
		}
		if !strings.HasPrefix(got.Reason, nestedURLReasonPrefix+" at position 1: ") {
			t.Fatalf("reason = %q", got.Reason)
		}
		if strings.Contains(got.Reason, canary) {
			t.Fatalf("reason echoes the query key: %q", got.Reason)
		}
		if !strings.Contains(got.Reason, "169.254.169.254") {
			t.Fatalf("reason dropped the blocked destination: %q", got.Reason)
		}
	})

	t.Run("scheme", func(t *testing.T) {
		got := s.Scan(context.Background(), "ftp://api.vendor.example/files")
		if got.Allowed || got.Scanner != ScannerScheme {
			t.Fatalf("scheme block = allowed:%v scanner:%s reason:%q", got.Allowed, got.Scanner, got.Reason)
		}
		if strings.Contains(strings.ToLower(got.Reason), "ftp") {
			t.Fatalf("reason echoes the scheme: %q", got.Reason)
		}
		if got.Reason != "scheme not allowed: only http and https" {
			t.Fatalf("reason = %q", got.Reason)
		}
	})

	t.Run("benign", func(t *testing.T) {
		for _, raw := range []string{
			"https://api.vendor.example/v1?page=1",
			"https://api.vendor.example/v1?callback=docs",
			"https://a.b.c.example.co.uk/v1?q=pipelock",
			"http://api.vendor.example/v1",
		} {
			got := s.Scan(context.Background(), raw)
			if !got.Allowed {
				t.Fatalf("%s blocked: %s %s", raw, got.Scanner, got.Reason)
			}
		}
	})
}
