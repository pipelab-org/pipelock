// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestDecodedLengthAdmission(t *testing.T) {
	for _, tc := range []struct{ expression, boundary, below, at string }{
		{`MARK[0-9]{4}`, "", "MARK123", "MARK1234"},
		{`[=:]MARK[0-9]{4}`, `MARK[0-9]{4}`, "MARK123", ":MARK1234"},
		{`.{3}`, "", "éé", "ééé"},
		{`MARK(?:[0-9]{4})?`, "", "MAR", "MARK"},
		{`f{3}`, "", "ff", "ﬀf"},
		{`.{8}`, "", "\xff\xfe\xfd\xfc\xfb\xfa\xf9", "\ufdfa"},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			p := &compiledPattern{name: "Record", re: regexp.MustCompile(tc.expression)}
			if tc.boundary != "" {
				p.withoutLeftBoundary = regexp.MustCompile(tc.boundary)
			}
			sc := &Scanner{dlpPatterns: []*compiledPattern{p}, dlpPreFilter: newDLPPreFilter([]*compiledPattern{p})}
			for _, input := range []string{tc.below, tc.at} {
				normalized := normalize.ForDLP(input)
				admitted := sc.dlpPreFilter.admitsLength(normalized)
				want := sc.matchDLPPatterns(normalized, "test")
				if !admitted && (p.re.MatchString(normalized) || p.withoutLeftBoundary != nil && p.withoutLeftBoundary.MatchString(normalized)) {
					t.Fatal("unscreened regexp admitted a rejected candidate")
				}
				shared := &sharedDecodes{}
				got := shared.matchDecoded(decodedMatchKey{scanner: sc, text: input, encoding: "test"})
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("length admission changed findings for %q: got %+v want %+v", input, got, want)
				}
				if input == tc.at && len(got) == 0 {
					t.Fatal("boundary witness was not detected")
				}
				if input == tc.at && sc.dlpPreFilter.rejectsUnnormalizedLength(input) {
					t.Fatal("normalization-expanding witness was declined")
				}
				if input == tc.below && len(input) < sc.dlpPreFilter.minimumRunes && !sc.dlpPreFilter.rejectsUnnormalizedLength(input) {
					t.Fatal("non-expanding short witness was not declined")
				}
				if input == tc.below && admitted {
					t.Fatal("below-bound witness did not skip")
				}
			}
		})
	}
}
