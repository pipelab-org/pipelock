// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package testreceipt

import (
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestVisitPathCommandsIncludesConfigAndInheritedFlags(t *testing.T) {
	run := func(*cobra.Command, []string) {}
	root := &cobra.Command{Use: "test"}
	local := &cobra.Command{Use: "local", Run: run}
	local.Flags().String("config", "", "configuration file")
	parent := &cobra.Command{Use: "parent"}
	parent.PersistentFlags().String("dir", "", "evidence directory")
	parent.AddCommand(&cobra.Command{Use: "child", Run: run})
	root.AddCommand(local, parent, &cobra.Command{Use: "unrelated", Run: run})

	got := make(map[string]bool)
	VisitPathCommands(root, func(cmd *cobra.Command) { got[cmd.CommandPath()] = true })
	want := []string{"test local", "test parent child"}
	if paths := slices.Sorted(maps.Keys(got)); !slices.Equal(paths, want) {
		t.Fatalf("path commands = %v, want %v", paths, want)
	}
}

func TestOracleSubprocess(t *testing.T) {
	mode := os.Getenv("RECEIPT_ORACLE_CASE")
	if mode != "" {
		root := &cobra.Command{Use: "example"}
		root.AddCommand(&cobra.Command{Use: "read <path>", Run: func(*cobra.Command, []string) {}})
		plans := map[string][]ReceiptProbe{"read": {{Args: []string{"$file"}}}}
		if mode == "unclassified" {
			plans = nil
		}
		if mode == "stale" {
			plans["missing"] = []ReceiptProbe{{Args: []string{"$file"}}}
		}
		RunReceiptCommandOracle(t, root, func(args []string, out io.Writer) int {
			if _, err := os.ReadFile(filepath.Clean(args[1])); err != nil {
				t.Fatal(err)
			}
			if mode == "success" {
				return 0
			}
			_, _ = io.WriteString(out, "use pipelock verify-receipt")
			return 1
		}, plans, nil)
		return
	}
	for _, tc := range []struct {
		mode, want string
		fail       bool
	}{
		{"success", "without a receipt-profile verdict or refusal", true},
		{"refusal", "", false},
		{"unclassified", "classify path-taking command read", true},
		{"stale", "stale receipt oracle probe for missing", true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestOracleSubprocess$") // #nosec G204 -- rerun this test binary with a fixed selector.
			cmd.Env = append(os.Environ(), "RECEIPT_ORACLE_CASE="+tc.mode, "GORACE=atexit_sleep_ms=0")
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.fail || !strings.Contains(string(out), tc.want) {
				t.Fatalf("failure=%t, output=%s", err != nil, out)
			}
		})
	}
}

func TestOracleRefusalInProcess(t *testing.T) {
	root := &cobra.Command{Use: "example"}
	root.AddCommand(&cobra.Command{Use: "read <path>", Run: func(*cobra.Command, []string) {}})
	RunReceiptCommandOracle(t, root, func(_ []string, out io.Writer) int {
		_, _ = io.WriteString(out, "use pipelock verify-receipt")
		return 1
	}, map[string][]ReceiptProbe{"read": {{Args: []string{"$file"}}}}, nil)
}

func TestReceiptProbeResultBranches(t *testing.T) {
	zero, one := 0, 1
	for _, tc := range []struct {
		code             int
		report           *int
		verdict, fixture string
		dir              bool
		location         string
		bad              bool
	}{
		{0, nil, "VALID", "signed", false, "", true},
		{1, &zero, "VALID", "signed", false, "", true},
		{0, &zero, "", "signed", false, "", true},
		{0, &zero, "VALID", "signed", false, "", false},
		{1, &one, "INVALID", "signed", false, "", true},
		{0, &zero, "VALID", "damaged", false, "", true},
		{0, &zero, "VALID", "renamed", false, "", true},
		{1, &one, "INVALID", "damaged", false, "", false},
		{0, &zero, "VALID", "nested", true, "", true},
		{0, &zero, "VALID", "nested", true, "child", false},
		{0, &zero, "VALID", "mixed", true, "", false},
	} {
		err := receiptProbeResultError(tc.code, tc.report, tc.verdict, tc.fixture, tc.dir, tc.location)
		if (err != nil) != tc.bad {
			t.Errorf("%+v: %v", tc, err)
		}
	}
}

func TestNestedReceiptProbeResult(t *testing.T) {
	zero := 0
	for _, tc := range []struct {
		name      string
		directory bool
		location  string
		wantErr   bool
	}{
		{"whole directory", true, "", true},
		{"selected child", true, "child", false},
		{"selected file", false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := receiptProbeResultError(0, &zero, "VALID", "nested", tc.directory, tc.location)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %t", err, tc.wantErr)
			}
		})
	}
}
