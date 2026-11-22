// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"testing"
)

// TestIssuerQueryReplayKeepsNestedURLChecks pins that replay relief covers a
// whole-value entropy score only. A value carrying a nested URL keeps its
// per-component checks even when replay evidence vouches for the exact value.
func TestIssuerQueryReplayKeepsNestedURLChecks(t *testing.T) {
	s := MustNew(testConfig())
	t.Cleanup(s.Close)
	const opaque = "kQ9zX4vB7mN2pL8rT5wY3jH6dF1sA0gC"
	vouched := map[string]bool{}
	ctx := WithIssuerQueryReplayAllowance(context.Background(), func(v string) bool { return vouched[v] })
	scan := func(value string) Result {
		t.Helper()
		return s.Scan(ctx, "https://api.vendor.example/app?ref="+url.QueryEscape(value))
	}

	if r := scan(opaque); r.Allowed {
		t.Fatal("premise: an unvouched opaque value must block")
	}
	vouched[opaque] = true
	if r := scan(opaque); !r.Allowed {
		t.Fatalf("a vouched whole value should be relieved, got %+v", r)
	}

	nested := "https://relay.vendor.example/" + opaque + "/view"
	if r := scan(nested); r.Allowed {
		t.Fatal("premise: an unvouched nested URL with an opaque path must block")
	}
	vouched[nested] = true
	if r := scan(nested); r.Allowed {
		t.Fatalf("replay evidence must not relieve nested URL component checks, got %+v", r)
	}
}
