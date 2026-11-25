// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCardReceiptNotLooserThanTraffic(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	spaced := cardtest.Grouped(pan, " ")
	uuidShape := pan[:8] + "-" + pan[8:12] + "-" + pan[12:16] + "-0000-000000000000"
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := MustNew(cfg)
	defer sc.Close()
	for _, text := range []string{
		"ref-" + pan,
		"id:abc-" + spaced,
		"x" + pan,
		"?ref=a-" + pan,
		"req-" + pan,
		uuidShape,
		"https://api.vendor.example/ref-" + pan,
		"https://api.vendor.example/?" + cardtest.Grouped(pan, "&"),
	} {
		if sc.ScanTextForDLP(t.Context(), text).Clean {
			t.Fatalf("traffic missed card: %q", text)
		}
		if sc.ScanTextForReceiptDLP(t.Context(), text).Clean {
			t.Fatalf("receipt looser than traffic: %q", text)
		}
	}
	for _, text := range []string{"order_" + pan, "xx" + pan, "abc" + pan + "def"} {
		if !sc.ScanTextForDLP(t.Context(), text).Clean || !sc.ScanTextForReceiptDLP(t.Context(), text).Clean {
			t.Fatalf("letter-bounded tail became a card: %q", text)
		}
	}
}
