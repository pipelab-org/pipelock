// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestSharedDLPWorkOnNaturalBodies(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	const size = 64 << 10
	// Baselines are observed work per corpus on the pre-gate scanner.
	// Use 25% headroom for fixed inputs and 50% for toolchain source files,
	// which can change between supported Go releases.
	cases := []struct {
		shape    string
		baseline scanner.SharedDLPWork
		extra    uint64
	}{
		{"prose", scanner.SharedDLPWork{DecodeBytes: 119644, DecodedViews: 23, MatchBytes: 209938, NormalizeBytes: 180626}, 4},
		{"short", scanner.SharedDLPWork{DecodeBytes: 119422, DecodedViews: 1945, MatchBytes: 156904, NormalizeBytes: 147641}, 4},
		{"b64json", scanner.SharedDLPWork{DecodeBytes: 239750, DecodedViews: 13189, MatchBytes: 1295054, NormalizeBytes: 770345}, 4},
		{"json_api", scanner.SharedDLPWork{DecodeBytes: 81128, DecodedViews: 3790, MatchBytes: 18066, NormalizeBytes: 74976}, 4},
		{"log_lines", scanner.SharedDLPWork{DecodeBytes: 147211, DecodedViews: 9178, MatchBytes: 347109, NormalizeBytes: 158647}, 4},
		{"go_source", scanner.SharedDLPWork{DecodeBytes: 119111, DecodedViews: 11444, MatchBytes: 291191, NormalizeBytes: 222314}, 2},
		{"markdown", scanner.SharedDLPWork{DecodeBytes: 192670, DecodedViews: 9781, MatchBytes: 1187271, NormalizeBytes: 720924}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.shape, func(t *testing.T) {
			var text string
			switch tc.shape {
			case "go_source":
				text = throughputGoSource(t, size)
			case "markdown":
				text = throughputMarkdown(t, size)
			default:
				text = throughputBody(tc.shape, size)
			}
			ctx, measured := scanner.MeasureSharedDLPWork(scanner.WithInboundDirection(t.Context()))
			result := sc.ScanTextForDLPInboundWithTypedCardView(ctx, text, text)
			if !result.Clean || result.Incomplete {
				t.Fatalf("benchmark corpus did not complete cleanly: %+v", result.Matches)
			}
			work := measured()
			for _, metric := range []struct {
				name           string
				work, baseline uint64
			}{
				{"decoder input bytes", work.DecodeBytes, tc.baseline.DecodeBytes},
				{"decoded views", work.DecodedViews, tc.baseline.DecodedViews},
				{"decoded matcher input bytes", work.MatchBytes, tc.baseline.MatchBytes},
				{"normalizer input bytes", work.NormalizeBytes, tc.baseline.NormalizeBytes},
			} {
				limit := metric.baseline + metric.baseline/tc.extra
				if metric.work == 0 || metric.work > limit {
					t.Errorf("%s: %d, want recorded work within %d (baseline %d)", metric.name, metric.work, limit, metric.baseline)
				}
			}
			t.Logf("%d input bytes: %+v", len(text), work)
		})
	}
}
