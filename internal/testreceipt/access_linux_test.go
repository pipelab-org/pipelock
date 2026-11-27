//go:build linux

// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package testreceipt

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCreatedV3StreamIgnoresExistingStreams(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.receipt-v3.jsonl")
	write("b.receipt-v3.jsonl")
	before, err := v3StreamNames(dir)
	if err != nil {
		t.Fatal(err)
	}
	if created, err := createdV3Stream(dir, before); err != nil || created {
		t.Fatalf("pre-existing streams counted as created: %t, %v", created, err)
	}
	write("unrelated.jsonl")
	if created, err := createdV3Stream(dir, before); err != nil || created {
		t.Fatalf("non-stream file counted as created: %t, %v", created, err)
	}
	write("c.receipt-v3.jsonl")
	if created, err := createdV3Stream(dir, before); err != nil || !created {
		t.Fatalf("new stream not detected: %t, %v", created, err)
	}
}

func TestObservedSuccessRules(t *testing.T) {
	const valid = `{"kind":"verify_result","verdict":"VALID","exit_code":0}`
	for _, tc := range []struct {
		name   string
		access observedAccess
		output string
		want   bool
	}{
		{"chain", observedAccess{file: true}, valid, true},
		{"verify-receipt", observedAccess{file: true}, valid, true},
		{"v3", observedAccess{file: true}, valid, true},
		{"other", observedAccess{file: true}, valid, false},
		{"chain", observedAccess{dir: true}, valid, false},
		{"chain", observedAccess{file: true}, `{"kind":"verify_result","verdict":"VALID"}`, false},
		{"chain", observedAccess{file: true}, `{"kind":"verify_result","verdict":"INVALID","exit_code":0}`, false},
		{"init", observedAccess{dir: true}, "pipelock verify-receipt --chain", true},
		{"doctor", observedAccess{dir: true}, "pipelock verify-receipt --chain", true},
		{"doctor", observedAccess{file: true}, "pipelock verify-receipt --chain", false},
		{"init", observedAccess{dir: true}, "no guidance", false},
	} {
		if got := validObservedSuccess(tc.name, tc.access, tc.output); got != tc.want {
			t.Errorf("%+v: got %t", tc, got)
		}
	}
}

func TestObservedOracleSubprocess(t *testing.T) {
	mode := os.Getenv("RECEIPT_ACCESS_CASE")
	if mode != "" {
		name := "chain"
		if mode == "runtime" || mode == "damaged-unreached" || mode == "multi" {
			name = "run"
		}
		root := &cobra.Command{Use: "example"}
		root.AddCommand(&cobra.Command{Use: name, Run: func(*cobra.Command, []string) {}})
		suite := AccessOracle{Root: root, Inputs: map[string][]string{name: {"$file"}}, MustOpen: []string{name}}
		if mode == "runtime" || mode == "damaged-unreached" || mode == "multi" {
			suite.Runtimes = []string{name}
		}
		if mode == "stale" {
			suite.Inputs["missing"] = []string{"$file"}
		}
		if mode == "excluded" || mode == "missing-test" {
			nameOfTest := "TestObservedSuccessRules"
			if mode == "missing-test" {
				nameOfTest = "TestDoesNotExist"
			}
			suite.Exclusions = map[string]AccessOracleExclusion{name: {Reason: "covered", Package: "internal/testreceipt", Test: nameOfTest}}
		}
		calls := 0
		suite.Invoke = func(t *testing.T, args []string, out io.Writer, _ string, _ bool) int {
			calls++
			if mode == "unreached" || (mode == "damaged-unreached" && calls > 1) {
				return 1
			}
			if mode == "multi" && calls == 1 {
				if err := os.WriteFile(filepath.Join(filepath.Dir(args[1]), "second.receipt-v3.jsonl"), []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.ReadFile(filepath.Clean(args[1])); err != nil {
				t.Fatal(err)
			}
			if mode == "multi" && calls > 1 {
				return 1
			}
			if mode == "valid" || mode == "damaged-unreached" {
				_, _ = io.WriteString(out, `{"kind":"verify_result","verdict":"VALID","exit_code":0}`)
			}
			return 0
		}
		RunObservedAccessOracle(t, suite)
		return
	}
	for _, tc := range []struct {
		mode, want string
		fail       bool
	}{
		{"missing", "without a v3 verification verdict", true},
		{"valid", "", false},
		{"runtime", "did not reject damaged v3 history", true},
		{"unreached", "fixture did not reach the evidence reader", true},
		{"damaged-unreached", "did not reach damaged v3 history", true},
		{"multi", "", false},
		{"stale", "stale observed-access inputs for missing", true},
		{"excluded", "", false},
		{"missing-test", "references missing test", true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestObservedOracleSubprocess$") // #nosec G204 -- rerun this test binary with a fixed selector.
			cmd.Env = append(os.Environ(), "RECEIPT_ACCESS_CASE="+tc.mode, "GORACE=atexit_sleep_ms=0")
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.fail || !strings.Contains(string(out), tc.want) {
				t.Fatalf("failure=%t, output=%s", err != nil, out)
			}
		})
	}
}

func TestObservedOracleInProcess(t *testing.T) {
	root := &cobra.Command{Use: "example"}
	root.AddCommand(&cobra.Command{Use: "chain", Run: func(*cobra.Command, []string) {}})
	RunObservedAccessOracle(t, AccessOracle{
		Root: root, Inputs: map[string][]string{"chain": {"$file"}}, MustOpen: []string{"chain"},
		Invoke: func(t *testing.T, args []string, out io.Writer, _ string, _ bool) int {
			if _, err := os.ReadFile(filepath.Clean(args[1])); err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(out, `{"kind":"verify_result","verdict":"VALID","exit_code":0}`)
			return 0
		},
	})
}

func TestAccessArgumentGeneration(t *testing.T) {
	root := &cobra.Command{Use: "example"}
	cmd := &cobra.Command{Use: "chain <dir> <file> <name> [optional]", Run: func(*cobra.Command, []string) {}}
	root.AddCommand(cmd)
	if got, want := accessOperands(cmd), []string{"$dir", "$file", "example"}; !slices.Equal(got, want) {
		t.Fatalf("operands %v want %v", got, want)
	}
	cmd.Flags().String("config", "", "config")
	cmd.Flags().String("events", "", "events")
	cmd.Flags().Bool("enabled", false, "enabled")
	for _, name := range []string{"config", "events", "enabled"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			t.Fatal(err)
		}
	}
	got := requiredAccessFlags(cmd, []string{"operand", "--", "tail"})
	want := []string{"operand", "--config", "$config", "--enabled=true", "--events", "$file", "--", "tail"}
	if !slices.Equal(got, want) {
		t.Fatalf("flags %v want %v", got, want)
	}
	if got := replaceAccessFlag([]string{"--events", "old"}, "events", "$file"); !slices.Equal(got, []string{"--events", "$file"}) {
		t.Fatal(got)
	}
	probes := accessFlagProbes(cmd, []string{"operand"}, nil)
	if len(probes) != 1 || !slices.Equal(probes[0].Args, []string{"operand", "--events", "$file"}) {
		t.Fatalf("probes: %+v", probes)
	}
	if probes := accessFlagProbes(cmd, nil, []ReceiptProbe{{Args: []string{"--events", "$file"}}}); len(probes) != 0 {
		t.Fatalf("duplicate probes: %+v", probes)
	}
}

func TestEvidenceWatchDistinguishesDirectoryAndStream(t *testing.T) {
	fixture := oracleFixtures(t)[0]
	calibrateEvidenceWatch(t, fixture)
	watch := watchEvidence(t, fixture.dir, fixture.file)
	if _, err := os.ReadDir(fixture.dir); err != nil {
		t.Fatal(err)
	}
	if got := watch.read(t); got != (observedAccess{dir: true}) {
		t.Fatalf("directory: %+v", got)
	}
	if _, err := os.ReadFile(fixture.file); err != nil {
		t.Fatal(err)
	}
	if got := watch.read(t); !got.file || got.dir {
		t.Fatalf("stream: %+v", got)
	}
}

func TestObservedOracleTreeAndRuntime(t *testing.T) {
	root := &cobra.Command{Use: "example"}
	group := &cobra.Command{Use: "group"}
	group.AddCommand(&cobra.Command{Use: "run", Run: func(*cobra.Command, []string) {}})
	root.AddCommand(group, &cobra.Command{Use: "skip", Run: func(*cobra.Command, []string) {}})
	calls := 0
	RunObservedAccessOracle(t, AccessOracle{
		Root: root, Inputs: map[string][]string{"group run": {"$file"}}, MustOpen: []string{"group run"}, Runtimes: []string{"group run"},
		Exclusions: map[string]AccessOracleExclusion{"skip": {Reason: "covered", Package: "internal/testreceipt", Test: "TestObservedSuccessRules"}},
		Invoke: func(t *testing.T, args []string, _ io.Writer, _ string, _ bool) int {
			calls++
			if calls == 1 {
				if err := os.WriteFile(filepath.Join(filepath.Dir(args[2]), "second.receipt-v3.jsonl"), []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.ReadFile(filepath.Clean(args[2])); err != nil {
				t.Fatal(err)
			}
			if calls == 1 {
				return 0
			}
			return 1
		},
	})
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
}

func TestAccessLocationFlagProbe(t *testing.T) {
	root := &cobra.Command{Use: "example"}
	cmd := &cobra.Command{Use: "read", Run: func(*cobra.Command, []string) {}}
	root.AddCommand(cmd)
	cmd.Flags().String("location", "", "location")
	got := accessFlagProbes(cmd, nil, []ReceiptProbe{{Args: []string{"--dir", "$dir"}, Directory: true}})
	if len(got) != 1 || !slices.Equal(got[0].Args, []string{"--dir", "$tmp", "--location", "evidence"}) {
		t.Fatalf("probes: %+v", got)
	}
}
