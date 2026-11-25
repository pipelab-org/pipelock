// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	legacy "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type benchmarkSyncFile struct {
	StreamFile
	syncs *atomic.Uint64
}

func (f benchmarkSyncFile) Sync() error {
	f.syncs.Add(1)
	return f.StreamFile.Sync()
}

func BenchmarkDurableActionWriter(b *testing.B) {
	b.Run("v3", func(b *testing.B) {
		opts := writerTestOptions(b.TempDir())
		storage := localWriterStorage()
		var syncs atomic.Uint64
		create := storage.createTemp
		storage.createTemp = func(dir, pattern string) (StreamFile, error) {
			file, err := create(dir, pattern)
			if err != nil {
				return nil, err
			}
			return benchmarkSyncFile{StreamFile: file, syncs: &syncs}, nil
		}
		writer, err := openStreamWriter(b.Context(), opts, storage)
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() {
			if err := writer.Close(context.Background(), nil); err != nil {
				b.Error(err)
			}
		})
		intent := writerTestIntent("")
		policy := CapturePolicy(opts.PolicyHash)
		syncs.Store(0)
		for b.Loop() {
			intent.ActionID = strconv.FormatUint(syncs.Load(), 10)
			if err := writer.WriteAction(b.Context(), intent, policy); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(syncs.Load())/float64(b.N), "file-syncs/record")
		b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "records/s")
	})
	b.Run("default", func(b *testing.B) {
		options := writerTestOptions(b.TempDir())
		rec, err := recorder.New(recorder.Config{Enabled: true, Dir: options.Dir}, nil, options.SigningKey)
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() {
			if err := rec.Close(); err != nil {
				b.Error(err)
			}
		})
		var syncs atomic.Uint64
		rec.SetSyncForTest(func(file *os.File) error {
			syncs.Add(1)
			return file.Sync()
		})
		intent := writerTestIntent("")
		emitter := legacy.NewEmitter(legacy.EmitterConfig{
			Recorder: rec, PrivKey: options.SigningKey, ConfigHash: options.PolicyHash,
			Actor: intent.Actor, Principal: intent.Principal,
		})
		if err := emitter.InitError(); err != nil {
			b.Fatal(err)
		}
		emit := legacy.EmitOpts{
			Target: intent.Target, Transport: intent.Transport,
			Method: intent.Method, Verdict: intent.Verdict,
		}
		for b.Loop() {
			emit.ActionID = strconv.FormatUint(syncs.Load(), 10)
			if err := emitter.EmitDurable(emit); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(syncs.Load())/float64(b.N), "file-syncs/record")
		b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "records/s")
	})
}

// BenchmarkConcurrentDurableActionWriter measures one admission and one
// observation per message on a shared writer.
func BenchmarkConcurrentDurableActionWriter(b *testing.B) {
	for _, connections := range []int{1, 4, 16, 64} {
		for _, format := range []string{"default", "v3"} {
			b.Run(fmt.Sprintf("%s/connections=%d", format, connections), func(b *testing.B) {
				benchmarkWriterMessages(b, format, connections, 0, benchmarkV3Writer)
			})
		}
	}
}

type benchmarkMessage func(context.Context, int) error

func benchmarkWriterMessages(b *testing.B, format string, connections int, gap time.Duration, openV3 func(*testing.B, *atomic.Uint64) (benchmarkMessage, func() error)) {
	var syncs atomic.Uint64
	var message benchmarkMessage
	var closeWriter func() error
	if format == "v3" {
		message, closeWriter = openV3(b, &syncs)
	} else {
		message, closeWriter = benchmarkLegacyWriter(b, &syncs)
	}
	syncs.Store(0)
	b.ResetTimer()
	var wg sync.WaitGroup
	for conn := range connections {
		wg.Go(func() {
			for i := conn; i < b.N; i += connections {
				if err := message(b.Context(), i); err != nil {
					b.Error(err)
					return
				}
				if gap != 0 && i+connections < b.N {
					timer := time.NewTimer(gap)
					select {
					case <-timer.C:
					case <-b.Context().Done():
						timer.Stop()
						return
					}
				}
			}
		})
	}
	wg.Wait()
	b.StopTimer()
	if err := closeWriter(); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "msgs/s")
	b.ReportMetric(float64(syncs.Load())/float64(b.N), "file-syncs/msg")
}

func benchmarkV3Writer(b *testing.B, syncs *atomic.Uint64) (benchmarkMessage, func() error) {
	return benchmarkV3WriterOptions(b, syncs, writerTestOptions(b.TempDir()))
}

func benchmarkV3WriterOptions(b *testing.B, syncs *atomic.Uint64, opts StreamWriterOptions) (benchmarkMessage, func() error) {
	storage := localWriterStorage()
	create := storage.createTemp
	storage.createTemp = func(dir, pattern string) (StreamFile, error) {
		file, err := create(dir, pattern)
		if err != nil {
			return nil, err
		}
		return benchmarkSyncFile{StreamFile: file, syncs: syncs}, nil
	}
	writer, err := openStreamWriter(b.Context(), opts, storage)
	if err != nil {
		b.Fatal(err)
	}
	gate := NewEffectGate(writer)
	policy := CapturePolicy(opts.PolicyHash)
	return func(ctx context.Context, id int) error {
		intent := writerTestIntent(strconv.Itoa(id))
		token, err := gate.Admit(ctx, intent, policy)
		if err != nil {
			return err
		}
		return token.ConfirmDelivery(ctx, func() (bool, error) { return true, nil })
	}, func() error { return writer.CloseUnsealed(context.Background()) }
}

func benchmarkLegacyWriter(b *testing.B, syncs *atomic.Uint64) (benchmarkMessage, func() error) {
	options := writerTestOptions(b.TempDir())
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: options.Dir}, nil, options.SigningKey)
	if err != nil {
		b.Fatal(err)
	}
	rec.SetSyncForTest(func(file *os.File) error {
		syncs.Add(1)
		return file.Sync()
	})
	intent := writerTestIntent("")
	emitter := legacy.NewEmitter(legacy.EmitterConfig{
		Recorder: rec, PrivKey: options.SigningKey, ConfigHash: options.PolicyHash,
		Actor: intent.Actor, Principal: intent.Principal,
	})
	if err := emitter.InitError(); err != nil {
		b.Fatal(err)
	}
	return func(_ context.Context, id int) error {
		return emitter.EmitDurable(legacy.EmitOpts{
			ActionID: strconv.Itoa(id), Target: intent.Target, Transport: intent.Transport,
			Method: intent.Method, Verdict: intent.Verdict,
		})
	}, rec.Close
}

func BenchmarkObservedOutcomeIdleFlush(b *testing.B) {
	for _, delay := range []time.Duration{0, time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond} {
		open := func(b *testing.B, syncs *atomic.Uint64) (benchmarkMessage, func() error) {
			opts := writerTestOptions(b.TempDir())
			opts.idleFlushDelay = &delay
			return benchmarkV3WriterOptions(b, syncs, opts)
		}
		for _, gap := range []time.Duration{0, time.Millisecond, 5 * time.Millisecond} {
			b.Run(fmt.Sprintf("delay=%s/gap=%s", delay, gap), func(b *testing.B) {
				benchmarkWriterMessages(b, "v3", 1, gap, open)
			})
		}
		for _, connections := range []int{4, 16, 64} {
			b.Run(fmt.Sprintf("delay=%s/connections=%d", delay, connections), func(b *testing.B) {
				benchmarkWriterMessages(b, "v3", connections, 0, open)
			})
		}
	}
}
