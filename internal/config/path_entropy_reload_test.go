// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func TestEntropyExclusionExpiryReloadDirection(t *testing.T) {
	t.Parallel()
	soon := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
	later := time.Now().UTC().AddDate(0, 0, 2).Format(time.DateOnly)
	for _, tc := range []struct {
		name, before, after string
		widened             bool
	}{
		{"unchanged", soon, soon, false},
		{"shorter", later, soon, false},
		{"permanent to temporary", "", soon, false},
		{"extension", soon, later, true},
		{"temporary to permanent", soon, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := Defaults()
			old.Mode = ModeStrict
			old.FetchProxy.Monitoring.PathEntropyExclusions = []PathEntropyExclusion{{Host: "api.vendor.example", PathPrefix: "/files/", Expires: tc.before}}
			old.FetchProxy.Monitoring.QueryEntropyParamExclusions = []QueryEntropyParamExclusion{{Host: "api.vendor.example", Path: "/files", Param: "id", Expires: tc.before}}
			next := old.Clone()
			next.FetchProxy.Monitoring.PathEntropyExclusions[0].Expires = tc.after
			next.FetchProxy.Monitoring.QueryEntropyParamExclusions[0].Expires = tc.after
			warnings := ValidateReload(old, next)
			want := 0
			if tc.widened {
				want = 2
			}
			if len(warnings) != want {
				t.Fatalf("warnings = %+v, want %d", warnings, want)
			}
			for _, warning := range warnings {
				if warning.Disposition != "" || !strings.Contains(warning.Message, "added") {
					t.Fatalf("extension must remain a rejectable downgrade: %+v", warning)
				}
			}
			if (old.CanonicalPolicyHash() == next.CanonicalPolicyHash()) != (tc.before == tc.after) {
				t.Fatal("expiry change lost its policy identity")
			}
		})
	}
}

// A reload that adds an exemption reduces detection coverage, and an operator
// running strict mode needs that surfaced rather than applied silently. A
// reload that only rewrites a reason or an owner is not a coverage change and
// must stay quiet, because a spurious downgrade warning is what strict mode
// refuses, so a noisy warning here would block a legitimate comment edit.

func pathEntropyReloadWarnings(t *testing.T, before, after []PathEntropyExclusion) []ReloadWarning {
	t.Helper()
	old := Defaults()
	old.FetchProxy.Monitoring.PathEntropyExclusions = before
	updated := Defaults()
	updated.FetchProxy.Monitoring.PathEntropyExclusions = after

	var out []ReloadWarning
	for _, w := range ValidateReload(old, updated) {
		if w.Field == "fetch_proxy.monitoring.path_entropy_exclusions" {
			out = append(out, w)
		}
	}
	return out
}

func joinWarnings(warnings []ReloadWarning) string {
	var b strings.Builder
	for _, w := range warnings {
		b.WriteString(w.Message)
		b.WriteString("\n")
	}
	return b.String()
}

var pathEntropyReloadEntry = PathEntropyExclusion{
	Scheme:     "https",
	Host:       "docs.vendor.example",
	PathPrefix: "/document/d/",
	Reason:     "service-issued document identifier",
	Owner:      "platform",
}

func TestPathEntropyExclusionsReloadWarnings(t *testing.T) {
	t.Parallel()

	second := PathEntropyExclusion{Scheme: "https", Host: "drive.vendor.example", PathPrefix: "/file/d/"}

	tests := []struct {
		name            string
		before          []PathEntropyExclusion
		after           []PathEntropyExclusion
		want            string
		wantDisposition []ReloadWarningDisposition
		wantNil         bool
		why             string
	}{
		{
			name:            "adding an exemption warns that coverage dropped",
			after:           []PathEntropyExclusion{pathEntropyReloadEntry},
			want:            "path entropy exclusions added: https://docs.vendor.example/document/d/",
			wantDisposition: []ReloadWarningDisposition{""},
			why:             "a reload that quietly reduces detection is the case this exists for",
		},
		{
			name:            "removing an exemption reports coverage restored",
			before:          []PathEntropyExclusion{pathEntropyReloadEntry},
			want:            "path entropy exclusions removed: https://docs.vendor.example/document/d/",
			wantDisposition: []ReloadWarningDisposition{ReloadWarningDispositionAdvisory},
		},
		{
			name:    "an unchanged list is silent",
			before:  []PathEntropyExclusion{pathEntropyReloadEntry},
			after:   []PathEntropyExclusion{pathEntropyReloadEntry},
			wantNil: true,
			why:     "idempotent reload must not manufacture a downgrade",
		},
		{
			name:    "reordering the same routes is silent",
			before:  []PathEntropyExclusion{pathEntropyReloadEntry, second},
			after:   []PathEntropyExclusion{second, pathEntropyReloadEntry},
			wantNil: true,
			why:     "entry order is authoring style, not policy",
		},
		{
			name:   "rewriting governance metadata is silent",
			before: []PathEntropyExclusion{pathEntropyReloadEntry},
			after: []PathEntropyExclusion{{
				Scheme:     "https",
				Host:       "docs.vendor.example",
				PathPrefix: "/document/d/",
				Reason:     "a corrected explanation",
				Owner:      "someone else",
				Expires:    pathEntropyReloadEntry.Expires,
			}},
			wantNil: true,
			why:     "strict mode refuses downgrades, so a comment edit must not read as one",
		},
		{
			name:   "an omitted scheme matches an explicit https entry",
			before: []PathEntropyExclusion{pathEntropyReloadEntry},
			after: []PathEntropyExclusion{{
				Host:       "docs.vendor.example",
				PathPrefix: "/document/d/",
			}},
			wantNil: true,
			why:     "https is the default, so spelling it out is not a policy change",
		},
		{
			name:            "swapping one route for another reports both directions",
			before:          []PathEntropyExclusion{pathEntropyReloadEntry},
			after:           []PathEntropyExclusion{second},
			want:            "added: https://drive.vendor.example/file/d/",
			wantDisposition: []ReloadWarningDisposition{"", ReloadWarningDispositionAdvisory},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := pathEntropyReloadWarnings(t, tt.before, tt.after)
			joined := joinWarnings(got)
			if tt.wantNil {
				if len(got) != 0 {
					t.Fatalf("expected no path-entropy reload warning (%s), got:\n%s", tt.why, joined)
				}
				return
			}
			if !strings.Contains(joined, tt.want) {
				t.Fatalf("expected a warning containing %q (%s), got:\n%s", tt.want, tt.why, joined)
			}
			if len(got) != len(tt.wantDisposition) {
				t.Fatalf("warning count = %d, want %d: %s", len(got), len(tt.wantDisposition), joined)
			}
			for i, warning := range got {
				if warning.Disposition != tt.wantDisposition[i] {
					t.Fatalf("warning %d disposition = %q, want %q", i, warning.Disposition, tt.wantDisposition[i])
				}
			}
		})
	}
}

// The swap case above asserts the added half; this pins that a swap reports the
// removal too, so replacing a route cannot look like a pure addition.
func TestPathEntropyExclusionsReloadSwapReportsRemoval(t *testing.T) {
	t.Parallel()

	got := joinWarnings(pathEntropyReloadWarnings(t,
		[]PathEntropyExclusion{pathEntropyReloadEntry},
		[]PathEntropyExclusion{{Scheme: "https", Host: "drive.vendor.example", PathPrefix: "/file/d/"}},
	))
	if !strings.Contains(got, "removed: https://docs.vendor.example/document/d/") {
		t.Fatalf("a swapped route did not report the removal, got:\n%s", got)
	}
}
