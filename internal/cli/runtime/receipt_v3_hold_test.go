// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
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
	depth := int64(held.CascadeDepth)
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
		Hold:    &v3.Hold{ID: held.DeferID, Policy: policy, Parent: held.ParentDeferID, CascadeDepth: &depth, Linkage: held.Linkage},
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
		cascade == nil || recovered.Hold.CascadeDepth == nil || *recovered.Hold.CascadeDepth != int64(cascade.CascadeDepth) ||
		recovered.Hold.Parent != cascade.ParentDeferID || recovered.Hold.Linkage != cascade.Linkage ||
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
			t.Fatalf("unexpected file in v3 evidence: %s", file.Name())
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
