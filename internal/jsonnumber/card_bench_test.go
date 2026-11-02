// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"strings"
	"testing"
)

func BenchmarkEscapeCardBoundaries(b *testing.B) {
	for _, tt := range []struct{ name, text string }{
		{"clean", `{"name":"ordinary report","count":42}`},
		{"markers", strings.Join([]string{"4111", "1111", "1111", "1111"}, NumberBoundary)},
	} {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = EscapeCardBoundaries(tt.text)
			}
		})
	}
}

func BenchmarkStringCardPiece(b *testing.B) {
	for _, tt := range []struct{ name, text string }{
		{"plain", "4111" + "1111" + "1111" + "1111"},
		{"separated", "4111 " + "1111-1111 1111"},
	} {
		b.Run(tt.name, func(b *testing.B) {
			if _, ok := stringCardPiece(tt.text); !ok {
				b.Fatal("fixture is not a card piece")
			}
			b.ReportAllocs()
			for b.Loop() {
				_, _ = stringCardPiece(tt.text)
			}
		})
	}
}

func BenchmarkCardRunsSetup(b *testing.B) {
	for _, tt := range []struct {
		name, text string
		run        func(string) []CardRun
	}{
		{"JSON", `["4111 1111","1111-1111"]`, func(text string) []CardRun { return CardRuns(text, 64) }},
		{"boundary", "4111 1111" + StringBoundary + "1111-1111", BoundaryCardRuns},
	} {
		b.Run(tt.name, func(b *testing.B) {
			if len(tt.run(tt.text)) == 0 {
				b.Fatal("fixture produced no card evidence")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = tt.run(tt.text)
			}
		})
	}
}
