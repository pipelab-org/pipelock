// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Limit each failed test to 50 MiB so a noisy producer cannot exhaust CI's artifact storage.
const evidenceLimit int64 = 50 << 20

type identityProblem struct {
	Identity    string `json:"identity"`
	Destination string `json:"destination,omitempty"`
	Kind        string `json:"kind"`
	Problem     string `json:"problem"`
	Expected    int32  `json:"expected"`
	Observed    int32  `json:"observed"`
}
type evidenceIdentities struct {
	Nonce         string            `json:"workload_nonce"`
	ListenerPorts []string          `json:"listener_ports"`
	Problems      []identityProblem `json:"problems"`
	ScanError     string            `json:"scan_error,omitempty"`
}
type evidenceManifest struct {
	CopiedBytes int64    `json:"copied_bytes"`
	Truncated   []string `json:"truncated"`
	Errors      []string `json:"errors"`
}

func retainEvidence(root, source, name string) error {
	if root == "" {
		return nil
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(root, strings.NewReplacer("/", "-", "\\", "-").Replace(name)+"-")
	if err != nil {
		return err
	}
	manifest := evidenceManifest{Truncated: []string{}, Errors: []string{}}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		run := filepath.Join(source, entry.Name())
		for _, file := range []string{"proxy.log", "listener-ports.json"} {
			copyEvidenceFile(run, dir, entry.Name(), file, &manifest)
		}
		recorder := filepath.Join(run, "recorder")
		walkErr := filepath.WalkDir(recorder, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(run, path)
			if err != nil {
				return err
			}
			// Recorder JSONL only: never traverse or copy private signing-key files.
			if d.Type().IsRegular() && ((filepath.Dir(rel) == "recorder" && strings.HasPrefix(d.Name(), "evidence-") && strings.HasSuffix(d.Name(), ".jsonl")) || (strings.HasPrefix(filepath.ToSlash(rel), "recorder/ael/") && strings.HasSuffix(filepath.ToSlash(rel), "/recorders/pipelock.jsonl"))) {
				copyEvidenceFile(run, dir, entry.Name(), rel, &manifest)
			}
			return nil
		})
		if walkErr != nil && !os.IsNotExist(walkErr) {
			manifest.Errors = append(manifest.Errors, walkErr.Error())
		}
		raw, err := os.ReadFile(filepath.Clean(filepath.Join(run, "result.json")))
		if err != nil {
			manifest.Errors = append(manifest.Errors, err.Error())
			continue
		}
		var res result
		if err := json.Unmarshal(raw, &res); err != nil {
			manifest.Errors = append(manifest.Errors, err.Error())
			continue
		}
		plan := newWorkload(res.Inputs.Workload.Seed, res.WarmupRequests, res.Requests)
		plan.runNonce = strings.TrimPrefix(res.Inputs.Workload.Tag, plan.tag()+"-r")
		if pool := res.Inputs.Workload.DestinationPool; pool != nil && len(pool.Ports) > 0 {
			plan.destinations = newDestinationPlan(plan.total(), pool.Ports)
		}
		ids := evidenceIdentities{Nonce: plan.runNonce, Problems: []identityProblem{}}
		if plan.destinations != nil {
			ids.ListenerPorts = plan.destinations.Ports
		}
		obs, scanErr := scanRecorder(filepath.Join(run, "recorder"), plan, "")
		if scanErr != nil {
			ids.ScanError = scanErr.Error()
		}
		if obs != nil && obs.aggregate == nil {
			for slot := range plan.total() {
				want := expectedFor(res.Mode, plan.blocked(slot))
				for k := range kindCount {
					got := obs.slots[slot].counts[k]
					if got == want[k] {
						continue
					}
					problem := "missing"
					if got > want[k] {
						problem = "duplicate"
						if want[k] == 0 {
							problem = "unexpected"
						}
					}
					p := identityProblem{Identity: plan.key(slot), Kind: k.String(), Problem: problem, Expected: want[k], Observed: got}
					if plan.destinations != nil {
						p.Destination = plan.destinations.authority(slot)
					}
					ids.Problems = append(ids.Problems, p)
				}
			}
		}
		b, err := json.MarshalIndent(ids, "", "  ")
		if err != nil {
			return err
		}
		// Metadata and all copied files share the same bound; manifest is kept separately.
		copyEvidenceBytes(dir, filepath.Join(entry.Name(), "missing-identities.json"), b, &manifest)

	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o600)
}

func copyEvidenceBytes(dir, rel string, b []byte, m *evidenceManifest) {
	remaining := max(int64(0), evidenceLimit-m.CopiedBytes)
	if int64(len(b)) > remaining {
		m.Truncated = append(m.Truncated, rel)
		b = b[:remaining]
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o750); err != nil {
		m.Errors = append(m.Errors, err.Error())
		return
	}
	if err := os.WriteFile(filepath.Join(dir, rel), b, 0o600); err != nil {
		m.Errors = append(m.Errors, err.Error())
		return
	}
	m.CopiedBytes += int64(len(b))
}

func copyEvidenceFile(run, dir, name, rel string, m *evidenceManifest) {
	path := filepath.Join(run, rel)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		m.Errors = append(m.Errors, err.Error())
		return
	}
	if !info.Mode().IsRegular() {
		m.Errors = append(m.Errors, fmt.Sprintf("not a regular file: %s", rel))
		return
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		m.Errors = append(m.Errors, err.Error())
		return
	}
	defer func() { _ = f.Close() }()
	remaining := max(int64(0), evidenceLimit-m.CopiedBytes)
	b, err := io.ReadAll(io.LimitReader(f, remaining+1))
	if err != nil {
		m.Errors = append(m.Errors, err.Error())
		return
	}
	copyEvidenceBytes(dir, filepath.Join(name, rel), b, m)
}

func retainOnFailure(t *testing.T, source string) {
	t.Helper()
	if root := os.Getenv("RECEIPT_LOAD_EVIDENCE_DIR"); root != "" {
		t.Cleanup(func() {
			if t.Failed() {
				if err := retainEvidence(root, source, t.Name()); err != nil {
					t.Errorf("retain evidence: %v", err)
				}
			}
		})
	}
}

func TestRetainEvidence(t *testing.T) {
	source := t.TempDir()
	run := filepath.Join(source, modeBest)
	recorder := filepath.Join(run, "recorder")
	if err := os.MkdirAll(filepath.Join(run, "keys"), 0o750); err != nil {
		t.Fatal(err)
	}
	plan := newWorkload(1, 0, 2)
	plan.runNonce = "abcd"
	plan.destinations = newDestinationPlan(2, []string{"12345"})
	writeSynthRecorder(t, recorder, plan, "", []synthReceipt{
		{kind: kindV1Allow, slot: 0, actionID: "one", target: "http://" + plan.destinations.authority(0)},
		{kind: kindV1Allow, slot: 0, actionID: "two", target: "http://" + plan.destinations.authority(0)},
		{kind: kindV1Block, slot: 1, actionID: "three", target: "http://" + plan.destinations.authority(1)},
	})
	res := result{Mode: modeBest, Requests: 2}
	res.Inputs.Workload = workloadReport{Seed: plan.seed, Tag: plan.tag(), DestinationPool: plan.destinations}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{"result.json": raw, "proxy.log": []byte("receipt_channel_broken\n"), "listener-ports.json": []byte(`{"proxy_port":1234}`), "keys/flight-recorder-signing.key": []byte("private")} {
		if err := os.WriteFile(filepath.Join(run, path), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(t.TempDir(), "evidence")
	if err := retainEvidence("", source, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("unexpected evidence: %v", err)
	}
	if err := retainEvidence(root, source, "test/failure"); err != nil {
		t.Fatal(err)
	}
	dirs, err := os.ReadDir(root)
	if err != nil || len(dirs) != 1 {
		t.Fatalf("directories: %v %v", dirs, err)
	}
	out := filepath.Join(root, dirs[0].Name())
	for _, path := range []string{"manifest.json", "best/proxy.log", "best/missing-identities.json", "best/listener-ports.json"} {
		if _, err := os.Stat(filepath.Join(out, path)); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join(out, "best/recorder/evidence-*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("recorder files: %v %v", files, err)
	}
	if _, err := os.Stat(filepath.Join(out, "best/keys/flight-recorder-signing.key")); !os.IsNotExist(err) {
		t.Fatalf("private key copied: %v", err)
	}
	raw, err = os.ReadFile(filepath.Clean(filepath.Join(out, "best/missing-identities.json")))
	if err != nil {
		t.Fatal(err)
	}
	var ids evidenceIdentities
	if err := json.Unmarshal(raw, &ids); err != nil {
		t.Fatal(err)
	}
	if ids.Nonce != "abcd" || len(ids.ListenerPorts) != 1 {
		t.Fatalf("identity evidence: %+v", ids)
	}
	kinds := map[string]bool{}
	for _, p := range ids.Problems {
		kinds[p.Problem] = true
	}
	for _, kind := range []string{"missing", "duplicate", "unexpected"} {
		if !kinds[kind] {
			t.Fatalf("missing %s from %+v scan=%s", kind, ids.Problems, ids.ScanError)
		}
	}
}

func TestEvidenceFailureHelper(t *testing.T) {
	if os.Getenv("RECEIPT_EVIDENCE_HELPER") != "1" {
		return
	}
	opt := smallOptions(t, newFakePipelock(t, "verifyfail"))
	opt.requests, opt.warmup = 2, 0
	res, err := runMode(context.Background(), opt, modeBest)
	if err != nil {
		t.Fatal(err)
	}
	if res.Integrity.Verdict != verdictFail {
		t.Fatal("expected harness integrity failure")
	}
	t.Fatal("intentional failure to exercise cleanup")
}

func TestEvidenceFailureCleanup(t *testing.T) {
	root := t.TempDir()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestEvidenceFailureHelper$") // #nosec G204 G702 -- rerun this test binary with a fixed selector.
	cmd.Env = append(os.Environ(), "RECEIPT_EVIDENCE_HELPER=1", "RECEIPT_LOAD_EVIDENCE_DIR="+root)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("helper unexpectedly passed: %s", out)
	}
	dirs, err := os.ReadDir(root)
	if err != nil || len(dirs) != 1 {
		t.Fatalf("cleanup evidence: %v %v", dirs, err)
	}
	for _, rel := range []string{"manifest.json", "best/proxy.log", "best/missing-identities.json"} {
		if _, err := os.Stat(filepath.Join(root, dirs[0].Name(), rel)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEvidenceCopyLimit(t *testing.T) {
	dir := t.TempDir()
	manifest := evidenceManifest{CopiedBytes: evidenceLimit - 2}
	copyEvidenceBytes(dir, "oversized", []byte("12345"), &manifest)
	b, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "oversized")))
	if err != nil || string(b) != "12" || manifest.CopiedBytes != evidenceLimit || len(manifest.Truncated) != 1 || manifest.Truncated[0] != "oversized" {
		t.Fatalf("bounded copy: %q %+v %v", b, manifest, err)
	}
}
