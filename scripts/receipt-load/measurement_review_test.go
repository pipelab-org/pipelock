// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReviewSummaryRefusesInvalidPopulation(t *testing.T) {
	for _, scenario := range []string{"failed", "mixed-config", "mixed-seed", "hash-prefix", "wrong-mode", "old-contract", "unknown-schema"} {
		t.Run(scenario, func(t *testing.T) {
			a := fakeResult(100, 80, 90, verdictPass, perfMeasured)
			b := fakeResult(900, 800, 850, verdictPass, perfMeasured)
			switch scenario {
			case "failed":
				b.Integrity.Verdict = verdictFail
			case "mixed-config":
				b.Inputs.Config.CanonicalSHA256 = strings.Repeat("d", 64)
			case "mixed-seed":
				b.Inputs.Workload.Seed = 2
			case "hash-prefix":
				b.Inputs.Binary.SHA256 = b.Inputs.Binary.SHA256[:63] + "c"
			case "wrong-mode":
				b.Mode = modeOff
			case "old-contract":
				b.Inputs.Harness.ContractVersion = "2"
			case "unknown-schema":
				b.SchemaVersion = 999
			}
			row := summaryRow(2, 1, modeRequired, 2, []result{a, b})
			if row[4] == verdictPass || row[7] != "" {
				t.Fatalf("unusable population reported integrity=%s median=%s", row[4], row[7])
			}
		})
	}
}

func TestReviewShellFailures(t *testing.T) {
	for _, code := range []string{"0", "7"} {
		t.Run("scope-exit-"+code, func(t *testing.T) {
			root := t.TempDir()
			scope := filepath.Join(root, "systemd-run")
			if err := os.WriteFile(scope, []byte("#!/bin/sh\nexit "+code+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Chmod(scope, 0o700); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(root, "matrix")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "./matrix.sh")
			cmd.Args = append(cmd.Args, newFakePipelock(t, "clean"), newFakePipelock(t, "harness"), out, "1", "1")
			cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "RECEIPT_LOAD_MODES=off")
			log, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("missing cell passed: %s", log)
			}
			if _, err := os.Stat(filepath.Join(out, "summary.csv")); err != nil {
				t.Fatalf("failure packet missing: %v %s", err, log)
			}
			if rows := readSummary(t, out); len(rows) != 12 {
				t.Fatalf("got %d rows", len(rows))
			}
		})
	}
	t.Run("run-build-failure", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "make"), []byte("#!/bin/sh\nexit 9\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Chmod(filepath.Join(root, "make"), 0o700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "./run.sh")
		cmd.Args = append(cmd.Args, filepath.Join(root, "out"))
		cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "RECEIPT_LOAD_REQUESTS=1")
		if log, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("build failure passed: %s", log)
		}
	})
}

func TestReviewWarmupErrorsInvalidateMeasurement(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "warmbadbody"))
	opt.requests, opt.warmup = 3, 3
	res, err := runMode(context.Background(), opt, modeOff)
	if err != nil {
		t.Fatal(err)
	}
	if res.Performance.Verdict != perfInvalid {
		t.Fatal("failed warmup reported a usable measurement")
	}
}

func TestReviewWindowDurationBoundary(t *testing.T) {
	rates := windowRates([]int64{int64(time.Millisecond)}, time.Second, time.Duration(1<<63-1))
	if len(rates) != 1 || rates[0].Requests != 1 || rates[0].Seconds != 1 {
		t.Fatalf("long valid window lost completions: %+v", rates)
	}
}

func TestReviewMatrixScopeFailureOverridesResult(t *testing.T) {
	root := t.TempDir()
	scope := filepath.Join(root, "systemd-run")
	if err := os.WriteFile(scope, []byte("#!/bin/sh\ncase \"$*\" in *\"/cpu-2/chains-1/\"*) shift 4; \"$@\" ;; esac\nexit 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Chmod(scope, 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "matrix")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "./matrix.sh")
	cmd.Args = append(cmd.Args, newFakePipelock(t, "clean"), newFakePipelock(t, "harness"), out, "1", "1")
	cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "RECEIPT_LOAD_MODES=off")
	if log, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("failed scope exited zero: %s", log)
	}
	packet := readResult(t, filepath.Join(out, "cpu-2", "chains-1", "sample-1", "off"))
	if packet.Integrity.Verdict != verdictPass {
		t.Fatal("positive control did not write a passing result")
	}
	for key, row := range readSummary(t, out) {
		if row["integrity"] == verdictPass || row["median_req_s"] != "" {
			t.Fatalf("scope failure disappeared from %s: %v", key, row)
		}
	}
}

// verifyTimeoutAfter reports whether "--verify-timeout value" appears as two
// arguments after the anchor argument in a newline-separated argv record. A pair
// placed before the program would be parsed by the launcher, not receipt-load.
func verifyTimeoutAfter(argv, anchor, value string) bool {
	at := strings.Index(argv, "\n"+anchor+"\n")
	return at >= 0 && strings.Index(argv[at:], "\n--verify-timeout\n"+value+"\n") > 0
}

func TestReviewMatrixForwardsVerifyTimeout(t *testing.T) {
	for _, value := range []string{"", "180s"} {
		t.Run("timeout="+value, func(t *testing.T) {
			root := t.TempDir()
			argv := filepath.Join(root, "argv")
			scope := filepath.Join(root, "systemd-run")
			if err := os.WriteFile(scope, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" -- >> \""+argv+"\"\nexit 0\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Chmod(scope, 0o700); err != nil {
				t.Fatal(err)
			}
			load := newFakePipelock(t, "harness")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "./matrix.sh")
			cmd.Args = append(cmd.Args, newFakePipelock(t, "clean"), load, filepath.Join(root, "matrix"), "1", "1")
			cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "RECEIPT_LOAD_MODES=off", "RECEIPT_LOAD_VERIFY_TIMEOUT="+value)
			// The fixture writes no results, so summarize exits nonzero; keep the
			// output for the failure message instead of asserting success.
			log, _ := cmd.CombinedOutput()
			data, err := os.ReadFile(filepath.Clean(argv))
			if err != nil {
				t.Fatal(err)
			}
			cells := strings.Split(strings.TrimSuffix("\n"+string(data), "--\n"), "--\n")
			if len(cells) != 12 {
				t.Fatalf("got %d cell launches, want 12\n%s", len(cells), log)
			}
			for i, cell := range cells {
				if !strings.HasPrefix(cell, "\n") {
					cell = "\n" + cell
				}
				forwarded := verifyTimeoutAfter(cell, load, value)
				if value == "" {
					forwarded = strings.Contains(cell, "--verify-timeout")
				}
				if forwarded != (value != "") {
					t.Fatalf("cell %d: verify timeout after the load binary=%v for %q\n%s", i, forwarded, value, cell)
				}
			}
		})
	}
}

func TestReviewRunForwardsVerifyTimeout(t *testing.T) {
	for _, value := range []string{"", "180s"} {
		t.Run("timeout="+value, func(t *testing.T) {
			root := t.TempDir()
			argv := filepath.Join(root, "argv")
			stubs := map[string]string{
				"make": "#!/bin/sh\nexit 0\n",
				"go":   "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + argv + "\"\nexit 0\n",
			}
			for name, body := range stubs {
				path := filepath.Join(root, name)
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Chmod(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "./run.sh")
			cmd.Args = append(cmd.Args, filepath.Join(root, "out"))
			cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "RECEIPT_LOAD_VERIFY_TIMEOUT="+value)
			if log, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("run.sh failed: %v\n%s", err, log)
			}
			data, err := os.ReadFile(filepath.Clean(argv))
			if err != nil {
				t.Fatal(err)
			}
			got := verifyTimeoutAfter("\n"+string(data), "./scripts/receipt-load", "180s")
			if value == "" {
				got = strings.Contains(string(data), "--verify-timeout")
			}
			if got != (value != "") {
				t.Fatalf("verify timeout forwarded=%v for %q; go argv:\n%s", got, value, data)
			}
		})
	}
}

func TestReviewSummaryEquivalentScopes(t *testing.T) {
	a, b := fakeResult(100, 80, 90, verdictPass, perfMeasured), fakeResult(200, 180, 190, verdictPass, perfMeasured)
	a.Inputs.Host.CgroupCPUQuota = "200000/100000 us (/scope-one)"
	b.Inputs.Host.CgroupCPUQuota = "200000/100000 us (/scope-two)"
	row := summaryRow(2, 1, modeRequired, 2, []result{a, b})
	if row[4] != verdictPass || row[7] != "150.0" {
		t.Fatalf("equal quotas rejected: %v", row)
	}
	b.Inputs.Host.CgroupCPUQuota = "400000/100000 us (/scope-two)"
	row = summaryRow(2, 1, modeRequired, 2, []result{a, b})
	if row[4] != verdictFail || row[7] != "" {
		t.Fatalf("unequal quotas accepted: %v", row)
	}
}

func TestMatrixProfilesRecordExactPlan(t *testing.T) {
	for _, profile := range []string{"", profileFull, profileRelease} {
		t.Run("profile="+profile, func(t *testing.T) {
			root := t.TempDir()
			argv := filepath.Join(root, "argv")
			scope := filepath.Join(root, "systemd-run")
			if err := os.WriteFile(scope, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" -- >> \""+argv+"\"\nexit 0\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Chmod(scope, 0o700); err != nil {
				t.Fatal(err)
			}
			load := newFakePipelock(t, "harness")
			out := filepath.Join(root, "matrix")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "./matrix.sh")
			cmd.Args = append(cmd.Args, newFakePipelock(t, "clean"), load, out)
			cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "RECEIPT_LOAD_PROFILE="+profile, "RECEIPT_LOAD_MODES=off,best,required", "RECEIPT_LOAD_VERIFY_TIMEOUT=180s")
			log, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("missing result files passed: %s", log)
			}
			data, err := os.ReadFile(filepath.Clean(argv))
			if err != nil {
				t.Fatalf("read argv: %v; %s", err, log)
			}
			got := map[string]bool{}
			scopes := strings.Split(strings.TrimSuffix(string(data), "--\n"), "--\n")
			for _, scope := range scopes {
				args := strings.Split(strings.TrimSpace(scope), "\n")
				at := slices.Index(args, load)
				if at < 0 {
					t.Fatalf("load missing from argv: %v", args)
				}
				flags := args[at+1:]
				cpu := flagValue(args, "-p")
				chain := flagValue(flags, "--chains")
				sample := filepath.Base(flagValue(flags, "--out"))
				if flagValue(flags, "--requests") != "20000" || flagValue(flags, "--warmup") != "1000" || flagValue(flags, "--concurrency") != "128" || flagValue(flags, "--verify-timeout") != "180s" {
					t.Fatalf("workload changed: %v", flags)
				}
				cores := strings.TrimSuffix(strings.TrimPrefix(cpu, "CPUQuota="), "00%")
				if want := string(filepath.Separator) + filepath.Join("cpu-"+cores, "chains-"+chain, sample); !strings.HasSuffix(flagValue(flags, "--out"), want) {
					t.Fatalf("output directory differs from plan: %v", flags)
				}
				if !slices.Contains(args[:at], "GOMAXPROCS="+cores) {
					t.Fatalf("quota and scheduler differ: %v", args)
				}
				for _, mode := range strings.Split(flagValue(flags, "--modes"), ",") {
					key := cores + "/" + chain + "/" + sample + "/" + mode
					if got[key] {
						t.Fatalf("duplicate result: %s", key)
					}
					got[key] = true
				}
			}
			want := map[string]bool{}
			for _, cpu := range []int{2, 4, 8} {
				for _, chain := range []int{1, 2, 4, 8} {
					for sample := 1; sample <= 3; sample++ {
						for _, mode := range []string{modeOff, modeBest, modeRequired} {
							selected := (mode == modeRequired && (chain == 1 || chain == 8)) || (sample == 1 && ((mode == modeOff && chain == 1) || (mode == modeBest && chain == 8)))
							if profile == profileRelease && !selected {
								continue
							}
							want[fmt.Sprintf("%d/%d/sample-%d/%s", cpu, chain, sample, mode)] = true
						}
					}
				}
			}
			if len(got) != len(want) {
				t.Fatalf("got %d results, want %d", len(got), len(want))
			}
			for key := range want {
				if !got[key] {
					t.Errorf("missing %s", key)
				}
			}
			expectedCount := 108
			if profile == profileRelease {
				expectedCount = 24
			}
			if len(got) != expectedCount {
				t.Fatalf("got %d results, want %d", len(got), expectedCount)
			}
			marker, err := os.ReadFile(filepath.Clean(filepath.Join(out, "profile")))
			expectedProfile := profile
			if profile == "" {
				expectedProfile = profileFull
			}
			if err != nil || string(marker) != expectedProfile+"\n" {
				t.Fatalf("profile marker %q: %v", marker, err)
			}
			rows := readSummary(t, out)
			samples := 0
			for _, row := range rows {
				n, err := strconv.Atoi(row["samples"])
				if err != nil {
					t.Fatal(err)
				}
				samples += n
			}
			if samples != expectedCount {
				t.Fatalf("summary planned %d samples, want %d", samples, expectedCount)
			}
		})
	}
}

func releaseSummaryFixture(t *testing.T) summaryParams {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "profile"), []byte(profileRelease+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := summaryParams{root: root, profile: profileRelease, samples: 3, cpus: []int{2, 4, 8}, chains: []int{1, 8}, modes: []string{modeOff, modeBest, modeRequired}}
	for _, cpu := range []int{2, 4, 8} {
		for _, mode := range []string{modeOff, modeBest, modeRequired} {
			chains, samples := []int{1, 8}, 3
			if mode == modeOff {
				chains, samples = []int{1}, 1
			}
			if mode == modeBest {
				chains, samples = []int{8}, 1
			}
			for _, chain := range chains {
				for sample := 1; sample <= samples; sample++ {
					r := fakeResult(150, 140, 145, verdictPass, perfMeasured)
					r.Requests, r.WarmupRequests, r.Concurrency = 20000, 1000, 128
					putResult(t, root, cpu, chain, sample, mode, r)
				}
			}
		}
	}
	return p
}

func TestReleaseSummaryRequiresEveryPlannedResult(t *testing.T) {
	p := releaseSummaryFixture(t)
	if _, err := summarizeCommand([]string{"--root", p.root, "--profile", profileRelease, "--samples", "3", "--chains", "1,8"}); err != nil {
		t.Fatal(err)
	}
	rows := readSummary(t, p.root)
	if len(rows) != 12 || rows["8/1/required"]["samples"] != "3" || rows["2/8/best"]["samples"] != "1" || rows["4/1/off"]["samples"] != "1" {
		t.Fatalf("wrong populations: %v", rows)
	}
	for _, path := range []string{"cpu-8/chains-8/sample-3/chains-8-required/result.json", "cpu-2/chains-1/sample-1/off/result.json", "cpu-4/chains-8/sample-1/chains-8-best/result.json"} {
		t.Run(path, func(t *testing.T) {
			p := releaseSummaryFixture(t)
			if err := os.Remove(filepath.Join(p.root, path)); err != nil {
				t.Fatal(err)
			}
			if err := writeSummary(p); err == nil {
				t.Fatal("missing planned result passed")
			}
		})
	}
}

func TestSummaryRefusesProfileMismatch(t *testing.T) {
	p := releaseSummaryFixture(t)
	if err := writeSummary(p); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	// All release results pass. Only the producer's declared profile differs.
	if err := os.WriteFile(filepath.Join(p.root, "profile"), []byte(profileFull+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeSummary(p); err == nil || !strings.Contains(err.Error(), "profile mismatch") {
		t.Fatalf("profile mismatch accepted: %v", err)
	}
	// A full summary must also refuse a release capture before judging its grid.
	if err := os.WriteFile(filepath.Join(p.root, "profile"), []byte(profileRelease+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.profile = profileFull
	if err := writeSummary(p); err == nil || !strings.Contains(err.Error(), "profile mismatch") {
		t.Fatalf("reverse profile mismatch accepted: %v", err)
	}
}

func TestReleaseSummaryRefusesInvalidPlanAndWorkload(t *testing.T) {
	for _, scenario := range []string{
		"missing-marker", "unreadable-marker", "unknown-profile", "samples", "cpus", "chains", "modes", "requests", "warmup", "concurrency",
		"all-requests", "all-warmup", "all-concurrency", "singleton-off", "singleton-best",
	} {
		t.Run(scenario, func(t *testing.T) {
			p := releaseSummaryFixture(t)
			switch scenario {
			case "missing-marker":
				if err := os.Remove(filepath.Join(p.root, "profile")); err != nil {
					t.Fatal(err)
				}
			case "unreadable-marker":
				if err := os.Remove(filepath.Join(p.root, "profile")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(p.root, "profile"), 0o750); err != nil {
					t.Fatal(err)
				}
			case "unknown-profile":
				p.profile = "unknown"
			case "samples":
				p.samples = 1
			case "cpus":
				p.cpus = []int{8}
			case "chains":
				p.chains = []int{1}
			case "modes":
				p.modes = []string{modeRequired}
			case "all-requests", "all-warmup", "all-concurrency", "singleton-off", "singleton-best":
				// Every sample of a population carries the wrong workload, or the
				// population has one sample, so sample identity comparison can't
				// refuse it; only the release workload guard can.
				for _, cpu := range []int{2, 4, 8} {
					for _, cell := range []struct {
						mode           string
						chain, samples int
					}{{modeOff, 1, 1}, {modeBest, 8, 1}, {modeRequired, 1, 3}, {modeRequired, 8, 3}} {
						for sample := 1; sample <= cell.samples; sample++ {
							r := fakeResult(150, 140, 145, verdictPass, perfMeasured)
							r.Requests, r.WarmupRequests, r.Concurrency = 20000, 1000, 128
							switch {
							case scenario == "all-requests":
								r.Requests--
							case scenario == "all-warmup":
								r.WarmupRequests--
							case scenario == "all-concurrency":
								r.Concurrency--
							case scenario == "singleton-off" && cell.mode == modeOff && cpu == 2:
								r.Requests--
							case scenario == "singleton-best" && cell.mode == modeBest && cpu == 4:
								r.Concurrency--
							}
							putResult(t, p.root, cpu, cell.chain, sample, cell.mode, r)
						}
					}
				}
			default:
				r := fakeResult(150, 140, 145, verdictPass, perfMeasured)
				r.Requests, r.WarmupRequests, r.Concurrency = 20000, 1000, 128
				switch scenario {
				case "requests":
					r.Requests--
				case "warmup":
					r.WarmupRequests--
				case "concurrency":
					r.Concurrency--
				}
				putResult(t, p.root, 2, 1, 1, modeRequired, r)
			}
			if err := writeSummary(p); err == nil {
				t.Fatal("invalid release capture passed")
			}
		})
	}
}

func TestMatrixRefusesInvalidReleaseSettings(t *testing.T) {
	for _, scenario := range []string{"profile", "requests", "samples", "modes"} {
		t.Run(scenario, func(t *testing.T) {
			profile, requests, samples, modes := profileRelease, "20000", "3", "off,best,required"
			switch scenario {
			case "profile":
				profile = "unknown"
			case "requests":
				requests = "1"
			case "samples":
				samples = "1"
			case "modes":
				modes = "required"
			}
			// A present systemd-run keeps the refusal on the settings check
			// instead of the missing-tool check, which also exits early.
			root := t.TempDir()
			scope := filepath.Join(root, "systemd-run")
			if err := os.WriteFile(scope, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Chmod(scope, 0o700); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(root, "matrix")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "./matrix.sh")
			cmd.Args = append(cmd.Args, newFakePipelock(t, "clean"), newFakePipelock(t, "harness"), out, requests, samples)
			cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "RECEIPT_LOAD_PROFILE="+profile, "RECEIPT_LOAD_MODES="+modes)
			log, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
				t.Fatalf("invalid settings did not exit 2: %v; %s", err, log)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("invalid settings created output: %v", err)
			}
		})
	}
}
