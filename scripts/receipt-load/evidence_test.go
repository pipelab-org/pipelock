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
	// Attribution is "aggregate" when the run's receipts cannot be tied to
	// individual workload identities; Problems is then empty and result.json
	// carries the aggregate counts.
	Attribution   string         `json:"attribution"`
	OrphanCounts  map[string]int `json:"orphan_counts,omitempty"`
	OrphanSamples []string       `json:"orphan_samples,omitempty"`
	ScanError     string         `json:"scan_error,omitempty"`
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
	runs, err := evidenceRuns(source, &manifest)
	if err != nil {
		return err
	}
	for _, name := range runs {
		run := filepath.Join(source, name)
		for _, file := range []string{"proxy.log", "listener-ports.json", "result.json"} {
			copyEvidenceFile(run, dir, name, file, &manifest)
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
				copyEvidenceFile(run, dir, name, rel, &manifest)
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
		ids := evidenceIdentities{Nonce: plan.runNonce, Problems: []identityProblem{}, Attribution: "identity"}
		if plan.destinations != nil {
			ids.ListenerPorts = plan.destinations.Ports
		}
		// Single-sink runs correlate receipts by the sink address, so scan with
		// the one the run recorded rather than an empty address.
		obs, scanErr := scanRecorder(filepath.Join(run, "recorder"), plan, recordedSinkAddress(run, &manifest))
		if scanErr != nil {
			ids.ScanError = scanErr.Error()
		}
		if obs != nil {
			ids.OrphanSamples = obs.orphanSamples
			for k := range kindCount {
				if obs.orphans[k] > 0 {
					if ids.OrphanCounts == nil {
						ids.OrphanCounts = map[string]int{}
					}
					ids.OrphanCounts[k.String()] = obs.orphans[k]
				}
			}
			if obs.aggregate != nil {
				ids.Attribution = "aggregate"
			}
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
		copyEvidenceBytes(dir, filepath.Join(name, "missing-identities.json"), b, &manifest)
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o600)
}

// evidenceRuns lists every run directory under source, relative to it. Some
// tests nest their output below the directory registered for retention, so a
// run is any directory holding result.json or proxy.log, at any depth. An
// unreadable descendant is recorded and skipped so readable runs are kept.
func evidenceRuns(source string, m *evidenceManifest) ([]string, error) {
	var runs []string
	err := filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if path == source {
				return err
			}
			m.Errors = append(m.Errors, err.Error())
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if d.Name() == "recorder" {
			return filepath.SkipDir
		}
		for _, marker := range []string{"result.json", "proxy.log"} {
			if info, statErr := os.Lstat(filepath.Join(path, marker)); statErr == nil && info.Mode().IsRegular() {
				rel, relErr := filepath.Rel(source, path)
				if relErr != nil {
					return relErr
				}
				runs = append(runs, rel)
				break
			}
		}
		return nil
	})
	return runs, err
}

// recordedSinkAddress reads the sink address a run saved in listener-ports.json.
func recordedSinkAddress(run string, m *evidenceManifest) string {
	raw, err := os.ReadFile(filepath.Clean(filepath.Join(run, "listener-ports.json")))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		m.Errors = append(m.Errors, err.Error())
		return ""
	}
	var ports struct {
		SinkAddress string `json:"sink_address"`
	}
	if err := json.Unmarshal(raw, &ports); err != nil {
		m.Errors = append(m.Errors, "listener-ports.json: "+err.Error())
		return ""
	}
	return ports.SinkAddress
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

// A single-sink run nested below the registered directory: retention must find
// it, correlate receipts through the recorded sink address, and keep orphans.
func TestRetainEvidenceSingleSinkNestedRun(t *testing.T) {
	for _, tt := range []struct {
		name          string
		listenerPorts string
		wantProblems  bool
	}{
		{"recorded sink address", `{"proxy_port":1234,"sink_address":"` + synthSink + `"}`, false},
		{"no recorded address", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := t.TempDir()
			run := filepath.Join(source, "nested", modeRequired)
			plan := newWorkload(1, 2, 40)
			plan.runNonce = "abcd"
			receipts := append(perfectReceipts(plan, modeRequired),
				synthReceipt{kind: kindV1Outcome, slot: 5, actionID: "stray", target: sinkTarget(synthSink, "wk=s1-m999999")})
			writeSynthRecorder(t, filepath.Join(run, "recorder"), plan, synthSink, receipts)
			res := result{Mode: modeRequired, Requests: 40, WarmupRequests: 2}
			res.Inputs.Workload = workloadReport{Seed: plan.seed, Tag: plan.tag()}
			raw, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			files := map[string]string{"result.json": string(raw)}
			if tt.listenerPorts != "" {
				files["listener-ports.json"] = tt.listenerPorts
			}
			for name, content := range files {
				if err := os.WriteFile(filepath.Join(run, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			root := t.TempDir()
			if err := retainEvidence(root, source, t.Name()); err != nil {
				t.Fatal(err)
			}
			dirs, err := os.ReadDir(root)
			if err != nil || len(dirs) != 1 {
				t.Fatalf("directories: %v %v", dirs, err)
			}
			out := filepath.Join(root, dirs[0].Name(), "nested", modeRequired)
			if _, err := os.Stat(filepath.Join(out, "result.json")); err != nil {
				t.Fatalf("result.json not retained: %v", err)
			}
			raw, err = os.ReadFile(filepath.Clean(filepath.Join(out, "missing-identities.json")))
			if err != nil {
				t.Fatal(err)
			}
			var ids evidenceIdentities
			if err := json.Unmarshal(raw, &ids); err != nil {
				t.Fatal(err)
			}
			if got := len(ids.Problems) > 0; got != tt.wantProblems {
				t.Fatalf("problems=%d want any=%v: %+v scan=%s", len(ids.Problems), tt.wantProblems, ids.Problems, ids.ScanError)
			}
			if !tt.wantProblems && (ids.OrphanCounts["v1_outcome"] != 1 || len(ids.OrphanSamples) == 0 || ids.Attribution != "identity") {
				t.Fatalf("orphan evidence: %+v", ids)
			}
		})
	}
}

func TestEvidenceRunsSkipsUnreadableDirectory(t *testing.T) {
	source := t.TempDir()
	for _, run := range []string{"a-readable", "b-locked/inner"} {
		if err := os.MkdirAll(filepath.Join(source, run), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, run, "proxy.log"), []byte("log\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	locked := filepath.Join(source, "b-locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o750) }) // #nosec G302 -- restore a test directory so TempDir cleanup can remove it.
	// Root or CAP_DAC_READ_SEARCH can still read it; probe instead of guessing.
	if _, err := os.ReadDir(locked); err == nil {
		t.Skip("this process can read a mode-0 directory")
	}
	manifest := evidenceManifest{}
	runs, err := evidenceRuns(source, &manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0] != "a-readable" || len(manifest.Errors) != 1 {
		t.Fatalf("runs=%v errors=%v", runs, manifest.Errors)
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
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("helper unexpectedly passed: %s", out)
	}
	// A failure before the intended one would also leave evidence behind.
	if !strings.Contains(string(out), "intentional failure to exercise cleanup") {
		t.Fatalf("helper failed before reaching its intended failure: %s", out)
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
