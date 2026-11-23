// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestRuntimeReceiptV3Reload(t *testing.T) {
	evidence := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "signer.key")
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("defer:\n  enabled: false\nflight_recorder:\n  enabled: true\n  dir: %q\n  signing_key_path: %q\n  receipt_format: v3\n  require_receipts: true\n", evidence, keyPath)
	configPath := writeServerTestConfig(t, body)
	s, err := NewServer(ServerOpts{
		ConfigFile: configPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{},
		ReverseProxy: true, ReverseListen: "127.0.0.1:0", ReverseUpstream: "https://api.vendor.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	writer := s.receiptWriter
	if writer == nil || s.liveReceiptEmitter() != nil {
		t.Fatal("expected v3 writer without a legacy emitter")
	}
	for _, tc := range []struct {
		name, old, new, wantErr string
	}{
		{name: "unchanged"},
		{name: "format", old: "receipt_format: v3", new: "receipt_format: legacy", wantErr: "receipt_format changed; restart required"},
		{name: "coverage", old: "require_receipts: true", new: "require_receipts: false", wantErr: "require_receipts changed; restart required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := strings.Replace(body, tc.old, tc.new, 1)
			cfg, err := config.LoadBytes([]byte(candidate))
			if err != nil {
				t.Fatal(err)
			}
			err = s.Reload(cfg)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("reload error = %v, want %q", err, tc.wantErr)
			}
			if s.receiptWriter != writer || s.liveReceiptEmitter() != nil {
				t.Fatal("reload changed the active receipt writer")
			}
		})
	}
	if err := s.closeReceiptV3(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", config.ReceiptFormatLegacy} {
		cfg := config.Defaults()
		cfg.Defer.Enabled = false
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = evidence
		cfg.FlightRecorder.SigningKeyPath = keyPath
		cfg.FlightRecorder.ReceiptFormat = name
		selected, err := receiptV3Selected(cfg)
		if name == "" {
			if err != nil || !selected {
				t.Fatalf("omitted format after cutover = %v, %v", selected, err)
			}
			cfg.Defer.Enabled = true
			if _, err := receiptV3Selected(cfg); err == nil || !strings.Contains(err.Error(), "deferred holds") {
				t.Fatalf("directory-selected v3 with deferred manager = %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "new evidence directory") {
			t.Fatalf("legacy format after cutover = %v, %v", selected, err)
		}
	}
	root, err := os.OpenRoot(evidence)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	files := root.FS()
	err = fs.WalkDir(files, ".", func(path string, entry fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(entry.Name(), "evidence-") && strings.HasSuffix(entry.Name(), ".jsonl") {
			// Operational JSONL is permitted, but a startup or reload may not write signed legacy receipts.
			data, err := fs.ReadFile(files, path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), "session_open") || strings.Contains(string(data), "proxy_decision") {
				return fmt.Errorf("legacy receipt in %s", path)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeReceiptReloadLegacyDefault(t *testing.T) {
	body := "defer:\n  enabled: false\nflight_recorder:\n  enabled: false\n"
	s, err := NewServer(ServerOpts{ConfigFile: writeServerTestConfig(t, body), Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	for _, suffix := range []string{"  receipt_format: legacy\n", ""} {
		cfg, err := config.LoadBytes([]byte(body + suffix))
		if err != nil {
			t.Fatal(err)
		}
		if err := checkV3ReloadCoverage(s.currentConfig(), cfg, false, false); err != nil {
			t.Fatalf("coverage comparison: %v", err)
		}
		if err := s.Reload(cfg); err != nil {
			t.Fatalf("reload %q: %v", suffix, err)
		}
	}
}

type heartbeatFaultFile struct {
	*os.File
	writes int
}

func (f *heartbeatFaultFile) Write(p []byte) (int, error) {
	f.writes++
	if f.writes == 2 {
		return 0, errors.New("heartbeat storage failure")
	}
	return f.File.Write(p)
}

func TestStandaloneMCPV3RequiredHeartbeatFailure(t *testing.T) {
	evidence := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "signer.key")
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("defer:\n  enabled: false\nflight_recorder:\n  enabled: true\n  dir: %q\n  signing_key_path: %q\n  receipt_format: v3\n  require_receipts: true\n", evidence, keyPath)
	open := func(ctx context.Context, cfg *config.Config, key ed25519.PrivateKey, _ *recorder.Recorder, _ posturebinding.Result, opts runtimeReceiptStreamOptions) (*v3.StreamWriter, error) {
		first := true
		return v3.OpenStreamWriter(ctx, v3.StreamWriterOptions{
			Dir: cfg.FlightRecorder.Dir, SigningKey: key, PolicyHash: v3.Digest(nil),
			Identity:  v3.Writer{Instance: "example", Product: "Pipelock", Version: "3"},
			Coverage:  v3.Coverage{ReceiptsRequired: true, Surfaces: opts.surfaces, RedactionRuleset: v3.Ruleset{ID: "example", Version: "1", Hash: v3.Digest(nil)}},
			Heartbeat: time.Second, OnHeartbeatError: opts.onHeartbeatError,
			CreateTempFile: func(dir, pattern string) (v3.StreamFile, error) {
				file, err := os.CreateTemp(dir, pattern)
				if err != nil || !first {
					return file, err
				}
				first = false
				return &heartbeatFaultFile{File: file}, nil
			},
		})
	}
	cmd := mcpProxyCmdWithReceiptWriter(audit.NewWithStream, 0, open)
	cmd.SetArgs([]string{"--config", writeServerTestConfig(t, body), "--listen", serverTestEphemeralListen, "--upstream", serverTestUpstreamURL})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(4*time.Second))
	defer cancel()
	err = cmd.ExecuteContext(ctx)
	if err == nil || !strings.Contains(err.Error(), "receipt heartbeat emission failed") {
		t.Fatalf("standalone command returned %v, want required heartbeat failure", err)
	}
}
