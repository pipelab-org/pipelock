// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestV3HoldCarriesLegacyRecoveryAttribution(t *testing.T) {
	legacyDir, streamDir := t.TempDir(), t.TempDir()
	cfg := config.Defaults()
	cfg.Defer.Enabled = true
	cfg.FlightRecorder.Dir = legacyDir
	manager := buildDeferManager(cfg, nil)
	held := deferred.HeldAction{
		DeferID: "approval", ActionID: "original-action", Target: "lookup",
		Surface: deferred.SurfaceMCPStdio, Method: "tools/call", Reason: "policy", SizeBytes: 1,
		Authority: deferred.AuthoritySnapshot{
			SessionID: "bound-session", SessionIDOriginal: "original-session", Principal: "local", Actor: "example",
		},
		Deadline: time.Now().Add(time.Minute), Resolve: func(deferred.Resolution) {},
	}
	parent := held
	parent.DeferID, parent.ActionID = "parent-approval", "parent-action"
	if err := manager.Hold(parent); err != nil {
		t.Fatal(err)
	}
	if err := manager.Hold(held); err != nil {
		t.Fatal(err)
	}
	pending, err := deferred.PendingJournal(manager.JournalPath())
	if err != nil || len(pending) != 2 {
		t.Fatalf("legacy journal hold unavailable: %v (%v)", pending, err)
	}
	for _, item := range pending {
		if item.DeferID == held.DeferID {
			held = item
		}
	}
	if held.CascadeDepth != 2 || held.ParentDeferID != parent.DeferID || held.Linkage != deferred.LinkageSessionPendingAncestor {
		t.Fatalf("journal did not preserve cascade attribution: %+v", held)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	legacyReceipts := filepath.Join(legacyDir, "receipts")
	rec, err := recorder.New(recorder.Config{Dir: legacyReceipts, Enabled: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: runtimeTestPolicyHash, Principal: held.Authority.Principal, Actor: held.Authority.Actor,
	})
	var log bytes.Buffer
	if err := recoverDeferredActions(manager, manager.JournalPath(), mcp.MCPProxyOpts{ReceiptEmitter: emitter, PolicyHash: runtimeTestPolicyHash}, &log); err != nil {
		t.Fatal(err)
	}
	legacy := readRuntimeActionRecords(t, legacyReceipts)
	if len(legacy) != 2 || legacy[1].DeferID != held.DeferID {
		t.Fatalf("wanted parent and child legacy recovery receipts, got %+v", legacy)
	}

	policy := deferred.ReceiptPolicyString(held.Policy, config.DeferResolutionPolicy{})
	opts := v3.StreamWriterOptions{
		Dir: streamDir, SigningKey: key, PolicyHash: v3.Digest(nil),
		Identity: v3.Writer{Instance: "example", Product: "Pipelock", Version: "3"},
		Coverage: v3.Coverage{
			ReceiptsRequired: true, Surfaces: []string{held.Surface},
			RedactionRuleset: v3.Ruleset{ID: "example", Version: "1", Hash: v3.Digest(nil)},
		},
	}
	writer, err := v3.OpenStreamWriter(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close(t.Context(), nil) })
	action := v3.Action{
		ActionID: held.ActionID, ActionType: "read", Actor: held.Authority.Actor, Principal: held.Authority.Principal,
		Caller: v3.Caller{Authn: "none"}, Data: v3.Data{SideEffectClass: "external_read", Reversibility: "full"},
		EffectBoundary: "approval_prompt", EffectRelation: "before", Phase: "hold", Verdict: "defer",
		Hold:    &v3.Hold{ID: held.DeferID, Policy: policy, Parent: held.ParentDeferID},
		Session: &v3.Session{ID: held.Authority.SessionID, OriginalID: held.Authority.SessionIDOriginal},
		Target:  held.Target, Method: held.Method, Transport: held.Surface, Pattern: held.Reason,
	}
	snapshot := v3.CapturePolicy("sha256:" + runtimeTestPolicyHash)
	if err := writer.WriteAction(t.Context(), action, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	reopened, err := v3.OpenStreamWriter(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	recovered := findV3RecoveryResolution(t, streamDir)
	old := legacy[1]
	var legacyPolicy deferred.ReceiptPolicy
	if err := json.Unmarshal([]byte(old.ResolutionPolicy), &legacyPolicy); err != nil {
		t.Fatal(err)
	}
	cascade := legacyPolicy.Cascade
	legacyPolicy.Cascade = nil
	legacyBounds, err := json.Marshal(legacyPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Hold == nil || recovered.Session == nil ||
		recovered.Hold.ID != old.DeferID || recovered.Hold.ResolutionSource != old.ResolutionSource ||
		recovered.Hold.ResolutionPolicy != string(legacyBounds) || recovered.Verdict != old.Verdict ||
		cascade == nil || recovered.Hold.Parent != "" ||
		recovered.Session.ID != old.SessionID || recovered.Session.OriginalID != old.SessionIDOriginal ||
		recovered.Target != old.Target || recovered.Transport != old.Transport || recovered.Pattern != old.Pattern ||
		recovered.ActionID != old.ParentActionID || recovered.Policy != snapshot.ActionPolicy() ||
		recovered.Principal != held.Authority.Principal || recovered.Actor != held.Authority.Actor {
		t.Fatalf("legacy and v3 recovery differ on retained fields: legacy=%+v v3=%+v", old, recovered)
	}
}

func findV3RecoveryResolution(t *testing.T, dir string) v3.Action {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".receipt-v3.jsonl") {
			continue
		}
		data, err := root.ReadFile(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		for line := range bytes.SplitSeq(data, []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var record struct {
				Payload v3.Common
			}
			if err := json.Unmarshal(line, &record); err != nil {
				t.Fatal(err)
			}
			if record.Payload.Kind != "action" {
				continue
			}
			var action v3.Action
			if err := json.Unmarshal(record.Payload.Body, &action); err != nil {
				t.Fatal(err)
			}
			if action.Phase == "resolution" {
				return action
			}
		}
	}
	t.Fatal("recovered hold resolution missing")
	return v3.Action{}
}

func TestMCPV3RestartSettlesUnsealedHold(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux subprocess signals")
	}
	const seedEnv = "PIPELOCK_TEST_RECEIPT_HOLD_DIR"
	const holdID = "pending-approval"
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if dir := os.Getenv(seedEnv); dir != "" {
		cfg := config.Defaults()
		cfg.FlightRecorder.Dir = dir
		cfg.FlightRecorder.Redact = false
		cfg.FlightRecorder.RequireReceipts = true
		writer, err := openRuntimeReceiptV3(t.Context(), cfg, key, nil, posturebinding.Result{}, runtimeReceiptStreamOptions{surfaces: []string{deferred.SurfaceMCPStdio}})
		if err != nil {
			t.Fatal(err)
		}
		action := v3.Action{
			ActionID: "held-call", ActionType: "read", Actor: "example", Principal: "local",
			Caller: v3.Caller{Authn: "none"}, Data: v3.Data{SideEffectClass: "external_read", Reversibility: "full"},
			EffectBoundary: "approval_prompt", EffectRelation: "before", Phase: "hold", Verdict: "defer",
			Hold: &v3.Hold{ID: holdID, Policy: "operator"}, Method: "tools/call", Target: "lookup",
			Transport: deferred.SurfaceMCPStdio,
		}
		if err := writer.WriteAction(t.Context(), action, v3.CapturePolicy("sha256:"+runtimeTestPolicyHash)); err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintln(os.Stdout, "hold confirmed")
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}

	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(30*time.Second))
	defer cancel()
	child := exec.CommandContext(ctx, exe, "-test.run=^TestMCPV3RestartSettlesUnsealedHold$") // #nosec G204 -- current test executable
	child.Env = append(os.Environ(), seedEnv+"="+dir)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	ready, readErr := bufio.NewReader(stdout).ReadString('\n')
	killErr := child.Process.Kill()
	waitErr := child.Wait()
	if ready != "hold confirmed\n" || readErr != nil || killErr != nil || waitErr == nil {
		t.Fatalf("hold writer did not stop after confirmation: readiness=%q read=%v kill=%v wait=%v", ready, readErr, killErr, waitErr)
	}

	// A switched runtime must ignore the legacy journal even when it is unreadable.
	journal := filepath.Join(dir, "deferred-actions.jsonl")
	if err := os.Mkdir(journal, 0o750); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "signer.key")
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := fmt.Sprintf("flight_recorder:\n  enabled: true\n  dir: %q\n  signing_key_path: %q\n  require_receipts: true\n  redact: false\ndefer:\n  enabled: true\n", dir, keyPath)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd := mcpProxyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--", "/bin/true"})
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(io.Discard)
	cmd.SetErr(&stderr)
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("restart: %v\n%s", err, &stderr)
	}
	action := findV3RecoveryResolution(t, dir)
	if action.ActionID != "held-call" || action.Hold == nil || action.Hold.ID != holdID ||
		action.Verdict != config.ActionBlock || action.Hold.ResolutionSource != deferred.SourceRestartRecovery {
		t.Fatalf("restart did not settle the signed hold: %+v", action)
	}
	if info, err := os.Stat(journal); err != nil || !info.IsDir() {
		t.Fatalf("restart changed the legacy journal sentinel: %v, %v", info, err)
	}
}

func TestMCPV3WebSocketCoverageUsesParsedScheme(t *testing.T) {
	dir := t.TempDir()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keyPath := filepath.Join(t.TempDir(), "signer.key")
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := fmt.Sprintf("flight_recorder:\n  enabled: true\n  dir: %q\n  signing_key_path: %q\n  require_receipts: true\n  redact: false\n  receipt_format: v3\n", dir, keyPath)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := mcpProxyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--upstream", "WSS://" + unavailableTCPAddr(t) + "/mcp"})
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(io.Discard)
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	if err := cmd.ExecuteContext(t.Context()); err == nil || !strings.Contains(stderr.String(), "proxying WS upstream") {
		t.Fatalf("expected WebSocket dial failure after setup: %v, %s", err, &stderr)
	}
	result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{
		Directory: true, Keys: []ed25519.PublicKey{key.Public().(ed25519.PublicKey)},
	})
	if err != nil || result.Verdict != "VALID" {
		t.Fatalf("WebSocket receipt stream = %s, %v", result.Verdict, err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.receipt-v3.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("receipt stream files = %v, %v", files, err)
	}
	data, err := os.ReadFile(filepath.Clean(files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"surfaces":["mcp_ws"]`)) {
		t.Fatal("signed stream did not advertise WebSocket coverage")
	}
}
