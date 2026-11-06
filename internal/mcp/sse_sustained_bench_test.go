// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// BenchmarkGenericSSEInjectionSustainedClean fills the retained tail with the
// first event, then measures a long stream of clean events against that tail.
func BenchmarkGenericSSEInjectionSustainedClean(b *testing.B) {
	cfg := config.Defaults()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	streamCfg := &config.GenericSSEScanning{Enabled: true, Action: config.ActionBlock}
	const events = 128
	prose := "The report is ready for review. "
	seed := strings.Repeat(prose, rollingTailSize/len(prose)+1)[:rollingTailSize]
	message := strings.Repeat(prose, 4)
	wire := "data: " + seed + "\n\n" + strings.Repeat("data: "+message+"\n\n", events)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	b.ResetTimer()
	for b.Loop() {
		if err := ScanGenericSSEStream(b.Context(), strings.NewReader(wire), io.Discard, nil, sc, streamCfg); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*(events+1)), "ns/event")
}
