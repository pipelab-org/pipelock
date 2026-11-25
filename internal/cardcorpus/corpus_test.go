// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cardcorpus

import (
	"encoding/base64"
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
		surface := "text"
		if tc.redaction {
			surface = "redact"
		}
		if tc.context == "path" {
			surface = "url"
		}
		if got := AllowedLoss(surface, tc.value); got != tc.want {
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
			surface := "text"
			if redaction {
				surface = "redact"
			}
			class := AllowedLoss(surface, c.Text)
			if !allowed[class] {
				t.Fatalf("case %s: unexpected allowed-loss class %q", c.ID, class)
			}
			if redaction && class != "" && class != "published" {
				t.Fatalf("case %s: redaction may only lose published examples, got %q", c.ID, class)
			}
		}
	}
}

func TestAllowedLossRenderedLoopholes(t *testing.T) {
	pan := number("4019", 16, 0)
	value := pan[:4] + "." + pan[4:]
	c := makeCase("hand", "visa", ".", "decimal-prefix", []string{pan[:4], pan[4:]})
	if got := AllowedLoss("text", c.Text); got != "" {
		t.Errorf("two-dot rendered input %q exempted as %s", c.Text, got)
	}
	c = Case{Value: value, Context: "bare", URL: "https://api.vendor.example/?value=" + value}
	if got := AllowedLoss("url", c.URL); got != "" {
		t.Errorf("URL input %q exempted as %s", c.URL, got)
	}
}

func TestAllowedLossSurfaceInputs(t *testing.T) {
	pan := number("4019", 16, 0)
	long := number("4019", 19, 2)
	otherVisa := number("4539", 16, 0)
	for _, tc := range []struct{ surface, input, want string }{
		{"text", otherVisa + "\t" + pan[:4] + "." + pan[4:], ""},
		{"unknown", pan[:4] + "." + pan[4:], ""},
		{"json-body", `{"value":"` + pan + `","value":"` + strings.Repeat("4242", 4) + `"}`, ""},
		{"json-body", `"` + strings.Repeat("4242", 4) + `" ` + pan, ""},
		{"text", "0." + pan[:4] + "." + pan[4:], ""},
		{"text", "https://api.vendor.example/?v=" + pan[:4] + "." + pan[4:], ""},
		{"json-body", `{"value":"https://api.vendor.example/?v=` + pan[:4] + "." + pan[4:] + `"}`, ""},
		{"json-body", `["` + pan[:4] + `.","` + pan[4:] + `"]`, ""},
		{"text", long[:16] + "\t" + long[16:18] + "\t" + long[18:], ""},
		{"text", pan[:4] + "." + pan[4:] + "-99", ""},
		{"text", pan[:8] + "\t" + pan[8:] + "-99", ""},
		{"text", pan + ".99", ""},
		{"text", "99." + pan, ""},
		{"text", pan[:4] + "\t" + pan[4:8] + " " + pan[8:], ""},
		{"url", "https://api.vendor.example/?v=" + pan[:8] + "%09" + pan[8:], ""},
	} {
		if got := AllowedLoss(tc.surface, tc.input); got != tc.want {
			t.Errorf("surface=%s input=%q got=%q want=%q", tc.surface, tc.input, got, tc.want)
		}
	}
}

func TestAllowedBareWarningBoundaries(t *testing.T) {
	pan := number("4019", 16, 1)
	for _, tc := range []struct {
		input string
		want  bool
	}{
		{pan, true},
		{`{"value":"` + pan + `"}`, true},
		{`["` + pan + `"]`, true},
		{"visa " + pan, false},
		{`{"card":"` + pan + `"}`, false},
		{pan + " 12/28", false},
		{"https://api.vendor.example/" + pan, false},
		{pan[:8] + " " + pan[8:], false},
		{`["` + pan[:8] + `","` + pan[8:] + `"]`, false},
	} {
		if got := AllowedBareWarning("text", tc.input); got != tc.want {
			t.Fatalf("%q got=%v want=%v", tc.input, got, tc.want)
		}
	}
}

func TestAllowedBareWarningRejectsMixedEncoding(t *testing.T) {
	pan := number("4019", 16, 1)
	input := `{"value":"` + pan + `","encoded":"` + base64.StdEncoding.EncodeToString([]byte(pan)) + `"}`
	if AllowedBareWarning("text", input) {
		t.Fatal("literal candidate authorized an encoded sibling")
	}
}

func TestAllowedBareWarningRejectsCorroboratedKeysAndTrailing(t *testing.T) {
	pan := number("4019", 16, 0)
	for _, key := range []string{"card_number", "card-no", "cardnumber"} {
		if AllowedBareWarning("json-body", `{"`+key+`":"`+pan+`"}`) {
			t.Errorf("corroborated key allowed: %s", key)
		}
	}
	if AllowedBareWarning("json-body", `{"value":"`+pan+`"} `+pan[:4]+" "+pan[4:8]+" "+pan[8:12]+" "+pan[12:]) {
		t.Fatal("trailing grouped card ignored")
	}
}
