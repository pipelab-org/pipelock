// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// BenchmarkDecodeBudget measures full text inspection rather than decoding
// alone, so matching and normalization costs of the retained views are included.
func BenchmarkDecodeBudget(b *testing.B) {
	for _, name := range []string{"json", "hex", "base64"} {
		b.Run(name, func(b *testing.B) {
			var body string
			switch name {
			case "json":
				body = `{"message":"` + strings.Repeat("!", 5_240_000-20) + `\u0061"}`
			case "hex":
				body = strings.Repeat("21", 3*1024*1024/2)
			case "base64":
				n := 9 * 1024 * 1024 / 4 * 3
				plain := bytes.Repeat([]byte{0xff}, n)
				body = base64.StdEncoding.EncodeToString(plain)
			}
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			sc := MustNew(cfg)
			b.Cleanup(sc.Close)
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for b.Loop() {
				result := sc.ScanTextForDLP(b.Context(), body)
				if !result.Clean {
					b.Fatalf("legitimate body refused: %v", result.Matches)
				}
			}
		})
	}
}
