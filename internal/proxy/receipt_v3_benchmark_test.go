// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

type benchmarkWebSocketFile struct {
	v3.StreamFile
	syncs *atomic.Uint64
}

func (f benchmarkWebSocketFile) Sync() error {
	f.syncs.Add(1)
	return f.StreamFile.Sync()
}

func BenchmarkConcurrentWebSocketFrameReceipts(b *testing.B) {
	for _, connections := range []int{1, 4, 16, 64} {
		for _, format := range []string{config.ReceiptFormatLegacy, config.ReceiptFormatV3} {
			b.Run(fmt.Sprintf("%s/connections=%d", format, connections), func(b *testing.B) {
				benchmarkConcurrentWebSocketFrames(b, format, connections)
			})
		}
	}
}

func benchmarkConcurrentWebSocketFrames(b *testing.B, format string, connections int) {
	cfg := config.Defaults()
	p := &Proxy{}
	var syncs atomic.Uint64
	var writer *v3.StreamWriter
	if format == config.ReceiptFormatV3 {
		var err error
		writer, err = v3.OpenStreamWriter(b.Context(), v3.StreamWriterOptions{
			Dir: b.TempDir(), SigningKey: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
			Identity:   v3.Writer{Instance: "benchmark", Product: "Pipelock", Version: "benchmark"},
			PolicyHash: "sha256:" + cfg.CanonicalPolicyHash(),
			Coverage: v3.Coverage{
				Surfaces: []string{"websocket"}, ReceiptsRequired: true,
				RedactionRuleset: v3.Ruleset{ID: "benchmark", Version: "1", Hash: "sha256:" + strings.Repeat("0", 64)},
			},
			CreateTempFile: func(dir, pattern string) (v3.StreamFile, error) {
				file, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				return benchmarkWebSocketFile{StreamFile: file, syncs: &syncs}, nil
			},
		})
		if err != nil {
			b.Fatal(err)
		}
		WithV3ReceiptWriter(writer)(p)
	}
	syncs.Store(0)
	payload := []byte("benchmark frame")
	b.ResetTimer()
	var wg sync.WaitGroup
	for conn := range connections {
		wg.Go(func() {
			relay := &wsRelay{proxy: p, cfg: cfg, targetURL: "wss://api.vendor.example/socket"}
			write := func() error {
				return wsutil.WriteServerMessage(io.Discard, ws.OpText, payload)
			}
			for i := conn; i < b.N; i += connections {
				if err := relay.writeReceiptFrame(b.Context(), boundaryDownstreamDelivery, write); err != nil {
					b.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
	b.StopTimer()
	if writer != nil {
		if err := writer.CloseUnsealed(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "msgs/s")
	b.ReportMetric(float64(syncs.Load())/float64(b.N), "file-syncs/msg")
}
