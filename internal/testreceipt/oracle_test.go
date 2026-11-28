// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package testreceipt

import (
	"errors"
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
		exclusions := map[string]string{}
		if mode == "overlap" {
			exclusions["read"] = "covered elsewhere"
		}
		if mode == "transcript" {
			root = &cobra.Command{Use: "example"}
			root.AddCommand(&cobra.Command{Use: "transcript-root <path>", Run: func(*cobra.Command, []string) {}})
			plans = map[string][]ReceiptProbe{"transcript-root": {{Args: []string{"$file"}}}}
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
		}, plans, exclusions)
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
		{"overlap", "has both a probe and an exclusion", true},
		{"transcript", "transcript-root did not identify the refused operation", true},
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
		{0, &zero, "INVALID", "mixed", true, "", true},
		{0, &zero, "INVALID", "nested", true, "child", true},
		{0, &zero, "INVALID", "nested", false, "", true},
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

func TestOracleDiagnosticRedaction(t *testing.T) {
	if got := oracleDiagnostic("secret payloadType bytes"); got != "command printed receipt bytes" {
		t.Fatal(got)
	}
	if got := oracleDiagnostic(strings.Repeat("x", 400)); len(got) != 380 {
		t.Fatalf("length %d", len(got))
	}
}

func TestReceiptProbeConfigAndExplicitLocation(t *testing.T) {
	fixture := oracleFixtures(t)[3]
	runReceiptProbe(t, func(args []string, out io.Writer) int {
		if len(args) != 7 || args[0] != "read" || args[1] != "--config" || args[3] != "--dir" || args[4] != fixture.dir || args[5] != "--location" || args[6] != "child" {
			t.Fatalf("args: %v", args)
		}
		data, err := os.ReadFile(filepath.Clean(args[2]))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), fixture.dir) || !strings.Contains(string(data), fixture.keyFile) {
			t.Fatalf("config: %s", data)
		}
		_, _ = io.WriteString(out, `{"kind":"verify_result","verdict":"VALID","exit_code":0}`)
		return 0
	}, "read", ReceiptProbe{Args: []string{"--config", "$config", "--dir", "$dir"}, Directory: true}, fixture, "child")
}

func TestReceiptOracleExplicitLocation(t *testing.T) {
	root := &cobra.Command{Use: "example"}
	cmd := &cobra.Command{Use: "read <dir>", Run: func(*cobra.Command, []string) {}}
	cmd.Flags().String("location", "", "location")
	root.AddCommand(cmd)
	locations := 0
	RunReceiptCommandOracle(t, root, func(args []string, out io.Writer) int {
		if slices.Contains(args, "--location") {
			locations++
		}
		_, _ = io.WriteString(out, "use pipelock verify-receipt")
		return 1
	}, map[string][]ReceiptProbe{"read": {{Args: []string{"$dir"}, Directory: true}}}, nil)
	if locations != 1 {
		t.Fatalf("explicit locations = %d", locations)
	}
}

func TestV3FixtureVariants(t *testing.T) {
	EachV3(t, func(t *testing.T, dir, path string) {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(path) != dir {
			t.Fatalf("path %s", path)
		}
		damaged := strings.HasSuffix(t.Name(), "/damaged")
		if got := string(data) == "damaged first line\n"; got != damaged {
			t.Fatalf("damaged = %t", got)
		}
	})
}

func TestRequiresV3Refusal(t *testing.T) {
	for _, suffix := range []string{"<path>", "--chain <path>"} {
		RequiresV3Refusal(t, errors.New("read: receipt v3 evidence is not supported by reader in this release; use 'pipelock verify-receipt "+suffix+"'"), "read", "reader")
	}
}

func TestVisitPathCommandsEvidenceFlag(t *testing.T) {
	root := &cobra.Command{Use: "example"}
	cmd := &cobra.Command{Use: "read", Run: func(*cobra.Command, []string) {}}
	cmd.Flags().String("evidence-source", "", "evidence file path")
	root.AddCommand(cmd)
	found := false
	VisitPathCommands(root, func(*cobra.Command) { found = true })
	if !found {
		t.Fatal("evidence flag was not discovered")
	}
}
