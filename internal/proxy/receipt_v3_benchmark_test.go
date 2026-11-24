// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/ed25519"
	"io"
	"strings"
	"testing"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

func BenchmarkWebSocketFrameReceipts(b *testing.B) {
	for _, format := range []string{config.ReceiptFormatLegacy, config.ReceiptFormatV3} {
		b.Run(format, func(b *testing.B) {
			cfg := config.Defaults()
			p := &Proxy{}
			if format == config.ReceiptFormatV3 {
				writer, err := v3.OpenStreamWriter(b.Context(), v3.StreamWriterOptions{
					Dir: b.TempDir(), SigningKey: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
					Identity:   v3.Writer{Instance: "benchmark", Product: "Pipelock", Version: "benchmark"},
					PolicyHash: "sha256:" + cfg.CanonicalPolicyHash(),
					Coverage: v3.Coverage{
						Surfaces: []string{"websocket"}, ReceiptsRequired: true,
						RedactionRuleset: v3.Ruleset{ID: "benchmark", Version: "1", Hash: "sha256:" + strings.Repeat("0", 64)},
					},
				})
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() {
					if err := writer.Close(context.Background(), nil); err != nil {
						b.Error(err)
					}
				})
				WithV3ReceiptWriter(writer)(p)
			}
			relay := &wsRelay{proxy: p, cfg: cfg, targetURL: "wss://api.vendor.example/socket"}
			payload := []byte("benchmark frame")
			write := func() error {
				return wsutil.WriteServerMessage(io.Discard, ws.OpText, payload)
			}
			for b.Loop() {
				if err := relay.writeReceiptFrame(b.Context(), boundaryDownstreamDelivery, write); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "frames/s")
		})
	}
}
