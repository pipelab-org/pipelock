// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func BenchmarkResponseWindows(b *testing.B) {
	b.Run("minified", func(b *testing.B) {
		const size = 1_215_035
		const statement = `function item(e){return e.enabled?{password:e.value,token:e.id,secret:e.data,memory:e.state}:null}const url="https://cdn.vendor.example/app";`
		body := bytes.Repeat([]byte(statement), (size+len(statement)-1)/len(statement))
		benchmarkResponseWindows(b, body[:size])
	})
	b.Run("encoded", func(b *testing.B) {
		const size = 1_215_035
		const statement = `function item(e){return e.enabled?{password:e.value,token:e.id,secret:e.data,memory:e.state}:null}const url="https://cdn.vendor.example/app";`
		const escaped = `const escapes=["\u0061","%26amp%3B","&lt;b&gt;neutral&lt;/b&gt;","+AGE-"];`
		chunk := strings.Repeat(statement, 50) + escaped
		body := bytes.Repeat([]byte(chunk), (size+len(chunk)-1)/len(chunk))
		benchmarkResponseWindows(b, body[:size])
	})
	b.Run("sample", func(b *testing.B) {
		benchmarkResponseWindows(b, responsePassFixture(b))
	})
}

func benchmarkResponseWindows(b *testing.B, body []byte) {
	b.Helper()
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	b.Cleanup(sc.Close)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	var incomplete bool
	for b.Loop() {
		result := sc.scanResponseBodyUncached(context.Background(), body, "", nil)
		if !result.Clean || result.Failed() {
			b.Fatalf("expected clean response, clean=%t findings=%d error=%q", result.Clean, len(result.Matches), result.ScanError)
		}
		incomplete = result.InspectionIncomplete
	}
	b.Logf("bytes=%d inspection_incomplete=%t", len(body), incomplete)
}
