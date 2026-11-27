//go:build linux

// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package testreceipt

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

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
		if mode == "runtime" {
			name = "run"
		}
		root := &cobra.Command{Use: "example"}
		root.AddCommand(&cobra.Command{Use: name, Run: func(*cobra.Command, []string) {}})
		suite := AccessOracle{Root: root, Inputs: map[string][]string{name: {"$file"}}, MustOpen: []string{name}}
		if mode == "runtime" {
			suite.Runtimes = []string{name}
		}
		suite.Invoke = func(t *testing.T, args []string, out io.Writer, _ string, _ bool) int {
			if _, err := os.ReadFile(filepath.Clean(args[1])); err != nil {
				t.Fatal(err)
			}
			if mode == "valid" {
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
