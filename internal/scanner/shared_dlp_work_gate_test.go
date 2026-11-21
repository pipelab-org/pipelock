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
	// Baselines cover work at the shared decoder and normalizer boundaries.
	// Fixed input bytes keep the required test independent of toolchain docs.
	// The paired benchmark measures whole scans, including matcher work.
	cases := []struct {
		shape    string
		baseline scanner.SharedDLPWork
	}{
		{"prose", scanner.SharedDLPWork{DecodeBytes: 119644, DecodedViews: 23, MatchBytes: 209938, NormalizeBytes: 180626}},
		{"short", scanner.SharedDLPWork{DecodeBytes: 119422, DecodedViews: 1945, MatchBytes: 156904, NormalizeBytes: 147641}},
		{"b64json", scanner.SharedDLPWork{DecodeBytes: 239750, DecodedViews: 13189, MatchBytes: 1295054, NormalizeBytes: 770345}},
		{"json_api", scanner.SharedDLPWork{DecodeBytes: 81128, DecodedViews: 3790, MatchBytes: 18066, NormalizeBytes: 74976}},
		{"log_lines", scanner.SharedDLPWork{DecodeBytes: 147211, DecodedViews: 9178, MatchBytes: 347109, NormalizeBytes: 158647}},
	}
	for _, tc := range cases {
		t.Run(tc.shape, func(t *testing.T) {
			text := throughputBody(tc.shape, size)
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
				limit := metric.baseline + metric.baseline/4
				if metric.work == 0 || metric.work > limit {
					t.Errorf("%s: %d, want recorded work within %d (baseline %d)", metric.name, metric.work, limit, metric.baseline)
				}
			}
			t.Logf("%d input bytes: %+v", len(text), work)
		})
	}
}
