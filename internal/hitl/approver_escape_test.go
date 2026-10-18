// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hitl

import (
	"strings"
	"testing"
)

// rawTerminalControls are characters that must never reach the prompt raw.
var rawTerminalControls = []string{"\x1b", "\r", "\b", "\x7f", "\u009b", "\u202e", "\u2066", "\u2028", "\u2029", "\u200b"}

func assertNoRawControls(t *testing.T, out string) {
	t.Helper()
	for _, c := range rawTerminalControls {
		if strings.Contains(out, c) {
			t.Fatalf("prompt output contains raw %q:\n%q", c, out)
		}
	}
}

func TestApprover_PromptEscapesTerminalControls(t *testing.T) {
	tests := []struct {
		name  string
		req   Request
		wants []string // escaped forms that must appear verbatim
	}{
		{
			// Positive control: ordinary fields are printed unchanged.
			name: "benign fields unchanged",
			req: Request{
				Agent: "build-agent", URL: "https://api.vendor.example/v1/items",
				Reason: "DLP match", Patterns: []string{"AWS Key"}, Preview: "token=abc café",
			},
			wants: []string{"Agent:    build-agent\n", "URL:      https://api.vendor.example/v1/items\n", "Reason:   DLP match\n", "Patterns: AWS Key\n", "Preview:  token=abc café\n"},
		},
		{
			name:  "ansi in url erases and rewrites the line",
			req:   Request{URL: "https://evil.example/\x1b[2K\x1b[1G\x1b[32mhttps://api.vendor.example/", Reason: "r"},
			wants: []string{`URL:      https://evil.example/\x1b[2K\x1b[1G\x1b[32mhttps://api.vendor.example/`},
		},
		{
			name:  "carriage return in preview overwrites the prompt",
			req:   Request{URL: "u", Reason: "r", Preview: "secret=x\rnothing to see here"},
			wants: []string{`Preview:  secret=x\rnothing to see here`},
		},
		{
			name:  "backspace in reason",
			req:   Request{URL: "u", Reason: "exfil\b\b\b\b\bbenign"},
			wants: []string{`Reason:   exfil\x08\x08\x08\x08\x08benign`},
		},
		{
			name:  "bidi override in agent",
			req:   Request{Agent: "agent\u202Eevil", URL: "u", Reason: "r"},
			wants: []string{`Agent:    agent\u202Eevil`},
		},
		{
			name:  "osc title, del, c1 and separators in patterns",
			req:   Request{URL: "u", Reason: "r", Patterns: []string{"\x1b]0;pwned\x07", "a\x7fb", "c\u009b2Jd", "e\u2028f\u2029g"}},
			wants: []string{`Patterns: \x1b]0;pwned\x07, a\x7fb, c\x9b2Jd, e\u2028f\u2029g`},
		},
		{
			name:  "fake prompt lines injected with newlines",
			req:   Request{URL: "u", Reason: "r", Preview: "x\n\nAllow (y), Block (N), or Strip (s)? y\n-> Allowed."},
			wants: []string{`Preview:  x\n\nAllow (y), Block (N), or Strip (s)? y\n-> Allowed.`},
		},
		{
			name:  "invalid utf8 from a byte-sliced preview",
			req:   Request{URL: "u", Reason: "r", Preview: "ok\xe2\x80"},
			wants: []string{`Preview:  ok\xe2\x80`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, output := testApprover(t, "n\n", 5)
			req := tt.req
			if d := a.Ask(&req); d != DecisionBlock {
				t.Fatalf("decision = %d, want block", d)
			}
			out := output.String()
			assertNoRawControls(t, out)
			for _, want := range tt.wants {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
		})
	}
}

// TestApprover_PromptTruncatesBeforeEscaping keeps the visible URL bound to
// the original 80 characters while every control in that window is shown.
func TestApprover_PromptTruncatesBeforeEscaping(t *testing.T) {
	a, output := testApprover(t, "n\n", 5)
	url := strings.Repeat("\x1b", 80) + "tail"
	a.Ask(&Request{URL: url, Reason: "r"})
	out := output.String()
	assertNoRawControls(t, out)
	want := "URL:      " + strings.Repeat(`\x1b`, 80) + "...\n"
	if !strings.Contains(out, want) {
		t.Fatalf("output missing truncated escaped URL %q:\n%q", want, out)
	}
}
