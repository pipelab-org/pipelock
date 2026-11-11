// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// BenchmarkTextDLPThroughput measures inbound text DLP on large bodies, the
// path an MCP media response or a download takes, in three credential-free
// shapes: prose in long lines, short lines, and JSON carrying base64 blobs.
//
// It uses only the scanner's exported API, so scripts/bench_throughput_gate.py
// can run this exact file against an older base commit and compare the two on
// one runner.
func BenchmarkTextDLPThroughput(b *testing.B) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := scanner.MustNew(cfg)
	b.Cleanup(s.Close)
	for _, shape := range []string{"prose", "short", "b64json"} {
		text := throughputBody(shape, 1<<20)
		b.Run(shape+"/1MiB", func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			for b.Loop() {
				ctx, release := scanner.WithSharedDecodes(scanner.WithInboundDirection(context.Background()))
				res := s.ScanTextForDLPInboundWithTypedCardView(ctx, text, text)
				release()
				if !res.Clean {
					b.Fatalf("benchmark input must scan clean: %+v", res.Matches)
				}
			}
		})
	}
}

// throughputBody returns deterministic, credential-free text of about n bytes.
func throughputBody(shape string, n int) string {
	words := []string{"the", "agent", "reads", "a", "document", "about", "river", "pipes", "valve", "pressure", "and", "flow"}
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		switch shape {
		case "prose":
			b.WriteString(words[i%len(words)])
			if i%97 == 96 {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
		case "short":
			fmt.Fprintf(&b, "%s %s %d\n", words[i%len(words)], words[(i*7)%len(words)], i%1000)
		default:
			// Distinct binary blobs derived from the record index. Each decodes to its own
			// view, which is what fills the scan's replay descriptor table on
			// large base64 bodies.
			raw := throughputBlob(i)
			fmt.Fprintf(&b, `{"id":%d,"blob":"%s","note":"%s"},`, i, base64.StdEncoding.EncodeToString(raw), words[i%len(words)])
		}
	}
	return b.String()
}

// throughputBlob returns 64 to 400 bytes of fixed, record-specific binary data
// from a SHA-256 chain, so every run scans the same bytes.
func throughputBlob(i int) []byte {
	sum := sha256.Sum256([]byte(strconv.Itoa(i)))
	n := 64 + int(binary.BigEndian.Uint16(sum[:2])%337)
	raw := make([]byte, 0, n+sha256.Size)
	for len(raw) < n {
		sum = sha256.Sum256(sum[:])
		raw = append(raw, sum[:]...)
	}
	return raw[:n]
}
