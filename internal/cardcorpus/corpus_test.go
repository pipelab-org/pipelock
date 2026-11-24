// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cardcorpus

import (
	"strings"
	"testing"
)

func TestAllowedLossPresentation(t *testing.T) {
	pan := number("4019", 16, 0)
	public := strings.Repeat("4242", 4)
	long := number("4019", 19, 2)
	for _, tc := range []struct {
		value, context, want string
		redaction            bool
	}{
		{pan[:4] + "." + pan[4:], "cell", "decimal", false},
		{pan + ".99", "bare", "", false},
		{"99." + pan, "bare", "", false},
		{pan[:8] + "\t" + pan[8:], "bare", "control-boundary", false},
		{long[:16] + "\t" + long[16:18] + "\t" + long[18:], "bare", "", false},
		{pan[:8] + "\r\n" + pan[8:], "bare", "control-boundary", false},
		{pan[:8] + " " + pan[8:], "bare", "", false},
		{pan[:4] + " - " + pan[4:], "bare", "", false},
		{pan[:4] + "." + pan[4:8] + "." + pan[8:], "bare", "", false},
		{pan[:4] + "." + pan[4:8] + "-" + pan[8:], "bare", "", false},
		{pan[:4] + "." + pan[4:], "path", "", false},
		{pan[:4] + "." + pan[4:], "bare", "", true},
		{public, "bare", "published", true},
		{`["4242","4242","4242","4242"]`, "json-strings", "published", false},
		{public + " " + pan, "bare", "", false},
		{public + "\t" + pan, "bare", "", false},
		{"9" + public, "bare", "", false},
	} {
		c := Case{Value: tc.value, Context: tc.context}
		if got := c.AllowedLoss(tc.redaction); got != tc.want {
			t.Errorf("value=%q context=%s redaction=%v got %q want %q", tc.value, tc.context, tc.redaction, got, tc.want)
		}
	}
}

func TestCasesAreDeterministicAndClassified(t *testing.T) {
	first, second := Cases(), Cases()
	if len(first) == 0 || len(first) != len(second) {
		t.Fatalf("case counts differ: %d vs %d", len(first), len(second))
	}
	if PartitionCount(15) != 4096 || PartitionCount(16) != 4096 {
		t.Fatalf("partition sample changed: %d, %d", PartitionCount(15), PartitionCount(16))
	}
	ids := make(map[string]struct{}, len(first))
	allowed := map[string]bool{"": true, "decimal": true, "control-boundary": true, "published": true}
	for i, c := range first {
		if c != second[i] {
			t.Fatalf("case %d differs between runs: %+v vs %+v", i, c, second[i])
		}
		if c.ID == "" || c.Value == "" || c.Text == "" || c.Category() == "" {
			t.Fatalf("case %d is incomplete: %+v", i, c)
		}
		if _, dup := ids[c.ID]; dup {
			t.Fatalf("duplicate case ID %q", c.ID)
		}
		ids[c.ID] = struct{}{}
		for _, redaction := range []bool{false, true} {
			class := c.AllowedLoss(redaction)
			if !allowed[class] {
				t.Fatalf("case %s: unexpected allowed-loss class %q", c.ID, class)
			}
			if redaction && class != "" && class != "published" {
				t.Fatalf("case %s: redaction may only lose published examples, got %q", c.ID, class)
			}
		}
	}
}
