// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"strings"
	"testing"
)

func TestRecordIssuerIDBlock(t *testing.T) {
	var absent *Metrics
	absent.RecordIssuerIDBlock(IssuerIDBlockHost)
	m := New()
	m.RecordIssuerIDBlock(IssuerIDBlockHost)
	m.RecordIssuerIDBlock(IssuerIDBlockHost)
	m.RecordIssuerIDBlock(IssuerIDBlockGlobal)
	m.RecordIssuerIDBlock("api.vendor.example")
	body := scrapeMetrics(t, m)
	for _, want := range []string{
		`pipelock_issuer_id_blocks_total{scope="host"} 2`,
		`pipelock_issuer_id_blocks_total{scope="global"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing metric %q", want)
		}
	}
	if strings.Contains(body, "api.vendor.example") {
		t.Fatal("unbounded scope became a metric label")
	}
}
