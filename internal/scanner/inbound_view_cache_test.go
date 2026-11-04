// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"
)

func inboundViewCacheScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := testConfig()
	cfg.DLP.ScanEnv = false
	sc, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(sc.Close)
	return sc
}

func TestInboundStructuralViewRemembersOnlyEmptyCleanResults(t *testing.T) {
	sc := inboundViewCacheScanner(t)
	ctx := context.Background()

	if r := sc.ScanTextForDLPInboundStructuralView(ctx, "content", "content"); !r.Clean || len(r.Matches) != 0 {
		t.Fatalf("clean key: %+v", r)
	}
	if !sc.inboundCleanViews.has(inboundCleanViewKey("content", "content")) {
		t.Fatal("clean key was not remembered")
	}

	secret := "AKIA" + strings.Repeat("Q", 16)
	for i := range 3 {
		r := sc.ScanTextForDLPInboundStructuralView(ctx, secret, secret)
		if r.Clean || len(r.Matches) == 0 {
			t.Fatalf("scan %d of a credential key: want a finding, got %+v", i, r)
		}
		full := sc.ScanTextForDLPInboundWithTypedCardView(ctx, secret, secret)
		if len(full.Matches) != len(r.Matches) {
			t.Fatalf("scan %d: structural %d matches, full %d", i, len(r.Matches), len(full.Matches))
		}
	}
	if sc.inboundCleanViews.has(inboundCleanViewKey(secret, secret)) {
		t.Fatal("a view with a finding was remembered")
	}
}

func TestInboundStructuralViewKeyKeepsTextAndCardApart(t *testing.T) {
	sc := inboundViewCacheScanner(t)
	ctx := context.Background()
	sc.ScanTextForDLPInboundStructuralView(ctx, "id", "id")
	if sc.inboundCleanViews.has(inboundCleanViewKey("id", "other")) {
		t.Fatal("a different card view shares the remembered verdict")
	}
	for _, pair := range [][4]string{
		{"a\x00b", "c", "a", "b\x00c"},
		{"ab", "c", "a", "bc"},
		{"1:a", "", "", "1:a"},
	} {
		if inboundCleanViewKey(pair[0], pair[1]) == inboundCleanViewKey(pair[2], pair[3]) {
			t.Fatalf("views %q/%q and %q/%q share a key", pair[0], pair[1], pair[2], pair[3])
		}
	}
}

func TestInboundStructuralViewBypassesMemoUnderAllowances(t *testing.T) {
	allowAll := func(string) bool { return true }
	cases := map[string]func(context.Context) context.Context{
		"oauth method": func(ctx context.Context) context.Context { return WithOAuthAuthorizationMethod(ctx, "GET") },
		"issuer query": func(ctx context.Context) context.Context {
			return WithIssuerQueryAllowance(ctx, func(string, string) bool { return true })
		},
		"issuer path":    func(ctx context.Context) context.Context { return WithIssuerPathAllowance(ctx, allowAll) },
		"issuer segment": func(ctx context.Context) context.Context { return WithIssuerSegmentAllowance(ctx, allowAll) },
	}
	for name, wrap := range cases {
		t.Run(name, func(t *testing.T) {
			sc := inboundViewCacheScanner(t)
			ctx := wrap(context.Background())
			if !scanContextCarriesAllowance(ctx) {
				t.Fatal("allowance not detected")
			}
			sc.ScanTextForDLPInboundStructuralView(ctx, "jsonrpc", "jsonrpc")
			if sc.inboundCleanViews.has(inboundCleanViewKey("jsonrpc", "jsonrpc")) {
				t.Fatal("a scan under an allowance was remembered")
			}
		})
	}
}

func TestInboundStructuralViewHitHonorsCanceledContext(t *testing.T) {
	sc := inboundViewCacheScanner(t)
	sc.ScanTextForDLPInboundStructuralView(context.Background(), "result", "result")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := sc.ScanTextForDLPInboundStructuralView(ctx, "result", "result")
	if r.Clean || !r.Incomplete || r.Err() == nil {
		t.Fatalf("canceled hit: want incomplete, got %+v", r)
	}
}

func TestInboundCleanViewsBudgetResets(t *testing.T) {
	var c inboundCleanViews
	c.remember(strings.Repeat("a", inboundStructuralViewBudget+1))
	if len(c.views) != 0 {
		t.Fatal("an over-budget view was remembered")
	}
	half := strings.Repeat("b", inboundStructuralViewBudget/2)
	c.remember(half + "1")
	c.remember(half + "2")
	if c.has(half+"1") || !c.has(half+"2") || c.bytes != len(half)+1 {
		t.Fatalf("budget overflow did not reset: entries=%d bytes=%d", len(c.views), c.bytes)
	}
	c.remember(half + "2")
	if c.bytes != len(half)+1 {
		t.Fatalf("repeat remember changed the byte count: %d", c.bytes)
	}
}
