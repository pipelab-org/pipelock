// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
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
		{name: "omit v3 format", old: "  receipt_format: v3\n"},
		{name: "restore explicit v3", old: "receipt_format: v3", new: "receipt_format: v3"},
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
	t.Run("validate direct reload candidate", func(t *testing.T) {
		cfg, err := config.LoadBytes([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Defer.Enabled = true
		if err := s.Reload(cfg); err == nil || !strings.Contains(err.Error(), "deferred holds") {
			t.Fatalf("reload with deferred holds = %v", err)
		}
		if s.receiptWriter != writer {
			t.Fatal("rejected reload replaced the live writer")
		}
	})
	for _, feature := range []struct {
		name   string
		enable func(*config.Config)
	}{
		{"dashboard_snapshot", func(c *config.Config) { c.DashboardSnapshot.Enabled = new(true) }},
		{"flight_recorder.evidence_health", func(c *config.Config) { c.FlightRecorder.EvidenceHealth.Enabled = new(true) }},
		{"flight_recorder.anchor", func(c *config.Config) { c.FlightRecorder.Anchor.LocalLog = "evidence.log" }},
	} {
		t.Run("refuse reload/"+feature.name, func(t *testing.T) {
			cfg, err := config.LoadBytes([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			// A directory-selected candidate only learns its effective format at runtime.
			cfg.FlightRecorder.ReceiptFormat = ""
			feature.enable(cfg)
			want := feature.name + " requires receipt_format: legacy"
			if err := s.Reload(cfg); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("reload error = %v, want %q", err, want)
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
	omitted := strings.Replace(body, "  receipt_format: v3\n", "", 1)
	restarted, err := NewServer(ServerOpts{
		ConfigFile: writeServerTestConfig(t, omitted), Stdout: &syncBuffer{}, Stderr: &syncBuffer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.cleanup)
	if restarted.receiptWriter == nil {
		t.Fatal("expected directory-selected v3 writer")
	}
	for _, tc := range []struct {
		name, candidate, wantErr string
	}{
		{"unchanged", omitted, ""},
		{"reject legacy", omitted + "  receipt_format: legacy\n", "receipt_format changed; restart required"},
		{"accept explicit v3", body, ""},
		{"return to omitted", omitted, ""},
	} {
		t.Run("directory selected/"+tc.name, func(t *testing.T) {
			cfg, err := config.LoadBytes([]byte(tc.candidate))
			if err != nil {
				t.Fatal(err)
			}
			err = restarted.Reload(cfg)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("reload error = %v, want %q", err, tc.wantErr)
			}
		})
	}
	if err := restarted.closeReceiptV3(); err != nil {
		t.Fatal(err)
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
	stderr := &syncBuffer{}
	s, err := NewServer(ServerOpts{ConfigFile: writeServerTestConfig(t, body), Stdout: &syncBuffer{}, Stderr: stderr})
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
	if strings.Contains(stderr.String(), "flight_recorder settings changed") {
		t.Fatalf("no-op receipt format reload emitted restart warning: %s", stderr.String())
	}
	switched := t.TempDir()
	if err := os.WriteFile(filepath.Join(switched, "stream.receipt-v3.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, format, dir string
	}{
		{"explicit v3", config.ReceiptFormatV3, ""},
		{"directory-selected v3", "", switched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.LoadBytes([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			cfg.FlightRecorder.ReceiptFormat, cfg.FlightRecorder.Dir = tc.format, tc.dir
			if err := s.Reload(cfg); err == nil || !strings.Contains(err.Error(), "receipt_format changed; restart required") {
				t.Fatalf("legacy reload error = %v, want format change rejection", err)
			}
		})
	}
	badDir := filepath.Join(switched, "not-a-directory")
	if err := os.WriteFile(badDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadBytes([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	cfg.FlightRecorder.Dir = badDir
	if err := s.Reload(cfg); err == nil || !strings.Contains(err.Error(), "read receipt evidence directory") {
		t.Fatalf("reload with invalid evidence directory = %v", err)
	}
}

func TestRuntimeReceiptReloadLegacyEvidenceHealth(t *testing.T) {
	const enabled = "  evidence_health:\n    enabled: true\n"
	const disabled = "  evidence_health:\n    enabled: false\n"
	for _, tc := range []struct {
		name, old, updated string
		warn               bool
	}{
		{"omitted to default", "", enabled, false},
		{"default to omitted", enabled, "", false},
		{"explicit change", enabled, disabled, true},
		{"explicit no change", disabled, disabled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf("flight_recorder:\n  enabled: true\n  sign_checkpoints: false\n  dir: %q\n", t.TempDir())
			stderr := &syncBuffer{}
			s, err := NewServer(ServerOpts{ConfigFile: writeServerTestConfig(t, body+tc.old), Stdout: &syncBuffer{}, Stderr: stderr})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.cleanup)
			cfg, err := config.LoadBytes([]byte(body + tc.updated))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Reload(cfg); err != nil {
				t.Fatal(err)
			}
			const evidenceWarning = "flight_recorder.evidence_health.enabled changed"
			log := stderr.String()
			if strings.Contains(log, evidenceWarning) != tc.warn || strings.Contains(log, "flight_recorder settings changed") {
				t.Fatalf("restart warning wanted = %v, logs: %s", tc.warn, log)
			}
		})
	}
}

func TestRuntimeReceiptV3IncompleteDrain(t *testing.T) {
	evidence := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "signer.key")
	pub, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("defer:\n  enabled: false\nflight_recorder:\n  enabled: true\n  dir: %q\n  signing_key_path: %q\n  receipt_format: v3\n", evidence, keyPath)
	s, err := NewServer(ServerOpts{ConfigFile: writeServerTestConfig(t, body), Listen: serverTestEphemeralListen, ListenChanged: true, allowEphemeralListenersForTesting: true, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := runJoined(t, ctx, s.Start, nil)
	select {
	case <-s.startupNotified():
	case err := <-result:
		t.Fatalf("Start returned before readiness: %v", err)
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("Start did not become ready")
	}
	s.agentDrainIncomplete.Store(true)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, proxy.ErrShutdownIncomplete) {
			t.Fatalf("Start returned %v, want incomplete drain", err)
		}
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("Start did not finish")
	}
	verified, err := v3.VerifyPaths(t.Context(), []string{evidence}, v3.Options{Directory: true, Keys: []ed25519.PublicKey{pub}})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Verdict != "VALID PREFIX, END UNPROVEN" {
		t.Fatalf("incomplete drain verified as %s", verified.Verdict)
	}
}

func TestStandaloneMCPV3ListenerDrainSeal(t *testing.T) {
	for _, tc := range []struct {
		name, verdict string
		incomplete    bool
	}{
		{"clean", "VALID", false},
		{"incomplete", "VALID PREFIX, END UNPROVEN", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, entered, release := heldDrainUpstream(t)
			evidence := t.TempDir()
			keyPath := filepath.Join(t.TempDir(), "signer.key")
			pub, key, err := signing.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if err := signing.SavePrivateKey(key, keyPath); err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf("defer:\n  enabled: false\nflight_recorder:\n  enabled: true\n  dir: %q\n  signing_key_path: %q\n  receipt_format: v3\n", evidence, keyPath)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cmd := mcpProxyCmdWithListenerTimeout(audit.NewWithStream, drainTestTimeout(tc.incomplete))
			cmd.SetContext(ctx)
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			log := &syncBuffer{}
			cmd.SetOut(io.Discard)
			cmd.SetErr(log)
			cmd.SetArgs([]string{"--config", writeServerTestConfig(t, body), "--listen", serverTestEphemeralListen, "--upstream", upstream})
			done := startDrainLifecycle(t, cancel, release, cmd.Execute)
			address := drainListenerAddress(t, log, "pipelock: MCP reverse proxy listening on ")
			requestDone := startDrainRequest(t, address, true)
			awaitDrainSignal(t, entered, "upstream request")
			cancel()
			if !tc.incomplete {
				waitDrainListenerClosed(t, address)
				release()
			}
			assertDrainResult(t, awaitDrainResult(t, done), tc.incomplete, "MCP HTTP listener")
			awaitDrainRequest(t, requestDone, tc.incomplete)
			release()
			verified, err := v3.VerifyPaths(t.Context(), []string{evidence}, v3.Options{Directory: true, Keys: []ed25519.PublicKey{pub}})
			if err != nil {
				t.Fatal(err)
			}
			if verified.Verdict != tc.verdict {
				t.Fatalf("verified as %s, want %s", verified.Verdict, tc.verdict)
			}
		})
	}
}

var errReceiptFixtureWrite = errors.New("receipt storage write failed")

type heartbeatFaultFile struct {
	*os.File
	writes int
}

func (f *heartbeatFaultFile) Write(p []byte) (int, error) {
	f.writes++
	if f.writes == 2 {
		return 0, errReceiptFixtureWrite
	}
	return f.File.Write(p)
}

func openReceiptWithWriteFault(ctx context.Context, cfg *config.Config, key ed25519.PrivateKey, opts runtimeReceiptStreamOptions, heartbeat time.Duration) (*v3.StreamWriter, error) {
	first := true
	return v3.OpenStreamWriter(ctx, v3.StreamWriterOptions{
		Dir: cfg.FlightRecorder.Dir, SigningKey: key, PolicyHash: v3.Digest(nil),
		Identity:  v3.Writer{Instance: "example", Product: "Pipelock", Version: "3"},
		Coverage:  v3.Coverage{ReceiptsRequired: true, Surfaces: opts.surfaces, RedactionRuleset: v3.Ruleset{ID: "example", Version: "1", Hash: v3.Digest(nil)}},
		Heartbeat: heartbeat, OnHeartbeatError: opts.onHeartbeatError,
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
		return openReceiptWithWriteFault(ctx, cfg, key, opts, time.Second)
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

func TestStandaloneMCPV3RequiresWriter(t *testing.T) {
	for _, tc := range []struct {
		name, surface, want string
		args                []string
		openErr             error
		sandbox             bool
	}{
		{name: "missing", surface: deferred.SurfaceMCPHTTPListener, want: "no v3 receipt writer is active", args: []string{"--listen", serverTestEphemeralListen, "--upstream", serverTestUpstreamURL}},
		{name: "HTTP upstream", surface: deferred.SurfaceMCPHTTPUpstream, args: []string{"--upstream", serverTestUpstreamURL}, openErr: errors.New("stream unavailable")},
		{name: "WebSocket upstream", surface: deferred.SurfaceMCPWS, args: []string{"--upstream", "ws://api.vendor.example/mcp"}, openErr: errors.New("stream unavailable")},
		{name: "stdio", surface: deferred.SurfaceMCPStdio, args: []string{"--", "example-mcp"}, openErr: errors.New("stream unavailable")},
		{name: "sandboxed stdio", surface: deferred.SurfaceMCPStdio, args: []string{"--sandbox", "--", "example-mcp"}, openErr: errors.New("stream unavailable"), sandbox: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sandbox && runtime.GOOS != "linux" {
				t.Skip("sandbox receipt surfaces require Linux")
			}
			_, key, err := signing.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(t.TempDir(), "signer.key")
			if err := signing.SavePrivateKey(key, keyPath); err != nil {
				t.Fatal(err)
			}
			yaml := fmt.Sprintf("defer:\n  enabled: false\nflight_recorder:\n  enabled: true\n  dir: %q\n  signing_key_path: %q\n  receipt_format: v3\n  require_receipts: true\n", t.TempDir(), keyPath)
			open := func(ctx context.Context, _ *config.Config, _ ed25519.PrivateKey, _ *recorder.Recorder, _ posturebinding.Result, opts runtimeReceiptStreamOptions) (*v3.StreamWriter, error) {
				want := []string{tc.surface}
				if tc.sandbox {
					want = append(want, "connect", "forward")
				}
				if !slices.Equal(opts.surfaces, want) {
					t.Fatalf("receipt surfaces = %v, want %v", opts.surfaces, want)
				}
				opts.onHeartbeatError(nil)
				if ctx.Err() != nil {
					t.Fatal("nil heartbeat error cancelled startup")
				}
				return nil, tc.openErr
			}
			cmd := mcpProxyCmdWithReceiptWriter(audit.NewWithStream, 0, open)
			cmd.SetArgs(append([]string{"--config", writeServerTestConfig(t, yaml)}, tc.args...))
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			err = cmd.ExecuteContext(t.Context())
			if tc.openErr != nil {
				if !errors.Is(err, tc.openErr) {
					t.Fatalf("startup error = %v, want %v", err, tc.openErr)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("startup error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRuntimeReceiptV3CoverageReloadLimits(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*config.Config)
	}{
		{"redaction", "redact changed", func(c *config.Config) { c.FlightRecorder.Redact = !c.FlightRecorder.Redact }},
		{"posture", "containment posture changed", func(c *config.Config) {
			c.FlightRecorder.RequireContainmentEvidence = !c.FlightRecorder.RequireContainmentEvidence
		}},
		{"surface", "coverage surfaces changed", func(c *config.Config) { c.WebSocketProxy.Enabled = !c.WebSocketProxy.Enabled }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, next := config.Defaults(), config.Defaults()
			tc.change(next)
			if err := checkV3ReloadCoverage(old, next, false, false); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("coverage reload error = %v, want %q", err, tc.want)
			}
		})
	}
	cfg := config.Defaults()
	cfg.ForwardProxy.Enabled = true
	cfg.TLSInterception.Enabled = true
	cfg.WebSocketProxy.Enabled = true
	want := []string{"fetch", "connect", "forward", "intercept", "websocket", "reverse", deferred.SurfaceMCPHTTPListener}
	if got := serverReceiptSurfaces(cfg, true, true); !slices.Equal(got, want) {
		t.Fatalf("receipt surfaces = %v, want %v", got, want)
	}
}

func TestRuntimeReceiptV3WriterPrerequisites(t *testing.T) {
	cfg := config.Defaults()
	cfg.FlightRecorder.Redact = false
	cfg.Defer.Enabled = false
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = t.TempDir()
	cfg.FlightRecorder.ReceiptFormat = config.ReceiptFormatV3
	cfg.FlightRecorder.SigningKeyPath = filepath.Join(t.TempDir(), "signer.key")
	if err := refuseUnwiredReceiptV3(cfg); err == nil || !strings.Contains(err.Error(), "unavailable in this runtime") {
		t.Fatalf("guard v3 startup error = %v", err)
	}
	for _, tc := range []struct{ input, want string }{
		{"invalid", "decode prior receipt signer key"},
		{"ff", "must be an Ed25519 public key"},
	} {
		cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{tc.input}
		writer, err := openRuntimeReceiptV3(t.Context(), cfg, nil, nil, posturebinding.Result{}, runtimeReceiptStreamOptions{})
		if err == nil || !strings.Contains(err.Error(), tc.want) || writer != nil {
			t.Fatalf("writer = %v, error = %v, want %q", writer, err, tc.want)
		}
	}
	pub, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = []string{hex.EncodeToString(pub)}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir()}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	writer, err := openRuntimeReceiptV3(t.Context(), cfg, key, rec, posturebinding.Result{
		Availability: posturebinding.AvailabilityAttested,
		Binding:      receipt.PostureBinding{CapsuleSHA256: v3.Digest(nil), SignerKeyID: "fixture", ContainedUID: "1000", ContainmentNonce: strings.Repeat("a", 32)},
	}, runtimeReceiptStreamOptions{surfaces: []string{"fetch"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestServerV3RefusesInvalidEvidenceDirectory(t *testing.T) {
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "signer.key")
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		evidence   func(*testing.T) string
	}{
		{"file", "read receipt evidence directory", func(*testing.T) string { return keyPath }},
		{"corrupt stream", "open v3 receipt writer", func(t *testing.T) string {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "invalid.receipt-v3.jsonl"), []byte("invalid evidence\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence := tc.evidence(t)
			yaml := fmt.Sprintf("defer:\n  enabled: false\nflight_recorder:\n  enabled: true\n  dir: %q\n  signing_key_path: %q\n  receipt_format: v3\n  require_receipts: true\n", evidence, keyPath)
			file := writeServerTestConfig(t, yaml)
			s, err := NewServer(ServerOpts{ConfigFile: file, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
			if s != nil {
				s.cleanup()
				t.Fatal("server opened invalid receipt evidence")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("server error = %v, want %q", err, tc.want)
			}
			if tc.name == "file" {
				_, _, err := runMCPProxyCommand(t, file)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("MCP error = %v, want %q", err, tc.want)
				}
			}
		})
	}
}

func TestRuntimeV3CloseReportsStorageFailure(t *testing.T) {
	cfg := config.Defaults()
	cfg.FlightRecorder.Dir = t.TempDir()
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	writer, err := openReceiptWithWriteFault(t.Context(), cfg, key, runtimeReceiptStreamOptions{surfaces: []string{"fetch"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{receiptWriter: writer}
	if err := s.closeReceiptV3(); !errors.Is(err, errReceiptFixtureWrite) {
		t.Fatalf("close error = %v, want storage failure", err)
	}
	if s.receiptWriter != nil {
		t.Fatal("server retained a closed receipt writer")
	}
}
