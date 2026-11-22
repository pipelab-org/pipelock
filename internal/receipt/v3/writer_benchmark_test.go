// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"os"
	"strconv"
	"sync/atomic"
	"testing"

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
