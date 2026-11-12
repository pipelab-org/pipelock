// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func BenchmarkUniformProfile(b *testing.B) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	for _, n := range []int{1 << 20, 2 << 20, 4 << 20} {
		b.Run(fmt.Sprintf("%dMiB", n>>20), func(b *testing.B) {
			text := strings.Repeat("x", n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.ScanTextForDLP(context.Background(), text)
			}
		})
	}
}

func BenchmarkUniformSibling(b *testing.B) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	for _, shape := range []struct{ name, unit string }{
		{"letter-a", "a"}, {"letter-A", "A"}, {"digit", "7"}, {"pair", "ab"}, {"alphabet", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"},
	} {
		text := strings.Repeat(shape.unit, (1<<20)/len(shape.unit))
		b.Run(shape.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				s.ScanTextForDLP(context.Background(), text)
			}
		})
	}
	text := strings.Repeat("x", 1<<20)
	b.Run("response", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s.ScanResponse(context.Background(), text)
		}
	})
}
