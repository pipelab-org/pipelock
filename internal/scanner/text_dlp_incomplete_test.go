// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestScanTextForDLPReportsIncomplete(t *testing.T) {
	sc := MustNew(config.Defaults())
	t.Cleanup(sc.Close)
	text := "key " + "AKIA" + "IOSFODNN7EXAMPLE"

	if got := sc.ScanTextForDLP(context.Background(), text); got.Incomplete || got.Clean {
		t.Fatalf("live context: want a complete dirty result, got %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, scan := range map[string]func(context.Context, string) TextDLPResult{
		"outbound": sc.ScanTextForDLP,
		"quiet":    sc.ScanTextForDLPQuiet,
		"inbound":  sc.ScanTextForDLPInbound,
		"body":     sc.ScanRequestBodyTextForDLP,
	} {
		t.Run(name, func(t *testing.T) {
			got := scan(ctx, text)
			if !got.Incomplete {
				t.Fatalf("ended context: want Incomplete, got %+v", got)
			}
			if got.Clean || len(got.Matches) == 0 {
				t.Fatalf("an incomplete result must keep the findings it has: %+v", got)
			}
		})
	}
}
