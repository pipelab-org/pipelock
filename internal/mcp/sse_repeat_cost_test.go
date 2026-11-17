// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// neutralSSEWire matches the diagnostic chat-completion delta shape:
// one tiny JSON event per token, no tool call and no secret.
func neutralSSEWire(events int) string {
	var b strings.Builder
	for i := range events {
		fmt.Fprintf(&b, "data: {\"choices\":[{\"delta\":{\"content\":\"ordinary output %d. \"}}]}\n\n", i)
	}
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

func BenchmarkNeutralChatSSE(b *testing.B) {
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	streamCfg := &config.GenericSSEScanning{Enabled: true, Action: config.ActionBlock}
	for _, n := range []int{100, 1000} {
		body := neutralSSEWire(n)
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for b.Loop() {
				err := ScanGenericSSEStream(context.Background(), strings.NewReader(body), io.Discard, nil, sc, streamCfg)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Metadata-bearing SSE has distinct rolling and payload views. Keep those
// workloads separate from data-only chat deltas when measuring scan reuse.
func BenchmarkAgentSSEWireShapes(b *testing.B) {
	for _, shape := range []struct{ name, event, payload string }{
		{name: "chat", payload: `{"choices":[{"delta":{"content":"ordinary output %d. "}}]}`},
		{name: "responses", event: "response.output_text.delta", payload: `{"type":"response.output_text.delta","item_id":"msg_123","output_index":0,"content_index":0,"sequence_number":1,"logprobs":[],"delta":"ordinary output %d. "}`},
		{name: "content_blocks", event: "content_block_delta", payload: `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ordinary output %d. "}}`},
	} {
		b.Run(shape.name, func(b *testing.B) {
			cfg := config.Defaults()
			cfg.DLP.ScanEnv = false
			cfg.Internal = nil
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			var wire strings.Builder
			for i := range 100 {
				if shape.event != "" {
					fmt.Fprintf(&wire, "event: %s\n", shape.event)
				}
				fmt.Fprintf(&wire, "data: "+shape.payload+"\n\n", i)
			}
			body := wire.String()
			streamCfg := &config.GenericSSEScanning{Enabled: true, Action: config.ActionBlock}
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := ScanGenericSSEStream(b.Context(), strings.NewReader(body), io.Discard, nil, sc, streamCfg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
