// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestCardCorroborationRedactionUnion(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	matcher := NewDefaultMatcher()
	for _, text := range []string{pan, cardtest.Grouped(pan, "-"), "visa " + pan[:4] + "." + pan[4:], "card number " + cardtest.Grouped(pan, "\t")} {
		if len(matcher.Scan(text)) == 0 {
			t.Fatalf("card not redacted: %q", text)
		}
	}
}

func TestCardCorroboratedJSONKeyRedaction(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, key := range []string{"card", "cardNumber", "pan"} {
		body := []byte(`{"` + key + `":"` + pan[:4] + `\t` + pan[4:] + `"}`)
		out, report, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{})
		if err != nil || report.TotalRedactions == 0 || strings.Contains(string(out), pan[4:]) {
			t.Fatalf("key=%s out=%s report=%+v err=%v", key, out, report, err)
		}
	}
}

func TestCardKeyNumericRunRefused(t *testing.T) {
	pan := cardtest.Issuer("453912341234123", 16)
	body := []byte(`{"card":[` + pan[:4] + `,` + pan[4:8] + `,` + pan[8:12] + `,` + pan[12:] + `]}`)
	if _, _, err := RewriteJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{}); err == nil {
		t.Fatal("payment-context numeric run was forwarded")
	}
}
