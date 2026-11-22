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
	b.Run("dense-encoded", func(b *testing.B) {
		// Encoded and nested islands every few hundred bytes give each
		// decoder hundreds of edits per view. That admits many sparse views
		// while every view keeps paying its own matching setup, and the walk
		// still ends incomplete. Compare its cost with the base revision.
		const size = 128 << 10
		const statement = `var a=function(b){return this.c+b.d};window.e=null;`
		islands := []string{`\u0069\u0067`, `&#105;&#103;`, `%69%67`, `+AGkAZw-`, `<i>x</i>`, `%26%23105%3B`, `\u0026#105;`, `&#37;69`, `%5Cu0069`, `&lt;b&gt;`}
		var chunk strings.Builder
		for _, island := range islands {
			chunk.WriteString(strings.Repeat(statement, 2))
			chunk.WriteString(island)
		}
		body := bytes.Repeat([]byte(chunk.String()), (size+chunk.Len()-1)/chunk.Len())
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
