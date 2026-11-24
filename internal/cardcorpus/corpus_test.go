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
	for _, tc := range []struct {
		value, context, want string
		redaction            bool
	}{
		{pan[:4] + "." + pan[4:], "cell", "decimal", false},
		{pan[:8] + "\t" + pan[8:], "bare", "control-boundary", false},
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
