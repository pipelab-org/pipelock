// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Natural shapes stay synthetic. They exercise the shared text scan without
// a customer payload or a forced compaction of the input.
func BenchmarkScanWorkShapes(b *testing.B) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := MustNew(cfg)
	defer sc.Close()
	shapes := []struct {
		name string
		text string
	}{
		{name: "markdown", text: scanWorkMarkdown(64 << 10)},
		{name: "code", text: scanWorkCode(64 << 10)},
		{name: "encoded", text: scanWorkEncoded(64 << 10)},
	}
	for _, shape := range shapes {
		b.Run(shape.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(shape.text)))
			for b.Loop() {
				result := sc.ScanTextForDLP(b.Context(), shape.text)
				if result.Incomplete || !result.Clean {
					b.Fatalf("shape %s incomplete=%v clean=%v matches=%d", shape.name, result.Incomplete, result.Clean, len(result.Matches))
				}
			}
		})
	}
}

func scanWorkMarkdown(n int) string {
	paragraph := "The service returns ordinary status text, a table of build numbers, and a link to https://docs.vendor.example/guide. No credential is present.\n\n"
	return scanWorkRepeat(paragraph, n)
}

func scanWorkCode(n int) string {
	paragraph := "func status() string {\n\treturn fmt.Sprintf(\"ready %d\", 42)\n}\n\n"
	return scanWorkRepeat(paragraph, n)
}

func scanWorkEncoded(n int) string {
	paragraph := "payload aGVsbG8gd29ybGQ= continues with prose and the percent form %68%65%6c%6c%6f.\n"
	return scanWorkRepeat(paragraph, n)
}

func scanWorkRepeat(paragraph string, n int) string {
	if len(paragraph) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(n)
	for b.Len() < n {
		b.WriteString(paragraph)
	}
	return b.String()[:n]
}
