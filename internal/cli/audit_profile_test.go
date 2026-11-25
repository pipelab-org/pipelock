// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestAuditCommandsRefuseReceiptProfiles(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, _, path string) {
		for _, args := range [][]string{{"report", "--input", path}, {"logs", "--file", path}} {
			t.Run(args[0], func(t *testing.T) {
				cmd := rootCmd()
				cmd.SetArgs(args)
				cmd.SetOut(io.Discard)
				cmd.SetErr(io.Discard)
				if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "pipelock verify-receipt") {
					t.Fatalf("expected receipt verification guidance, got %v", err)
				}
			})
		}
	})
	t.Run("stdin", func(t *testing.T) {
		path, _ := testreceipt.V3(t, t.TempDir(), false)
		cmd := rootCmd()
		cmd.SetArgs([]string{"report", "--input", "-"})
		cmd.SetIn(bytes.NewReader(append([]byte("\n  "), readOracleFile(t, path)...)))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "pipelock verify-receipt") {
			t.Fatalf("expected receipt verification guidance, got %v", err)
		}
	})
	t.Run("oversized line before profile", func(t *testing.T) {
		path, _ := testreceipt.V3(t, t.TempDir(), false)
		cmd := rootCmd()
		cmd.SetArgs([]string{"report", "--input", "-"})
		oversized := strings.NewReader(strings.Repeat("x", 1<<20) + "\n")
		cmd.SetIn(io.MultiReader(oversized, bytes.NewReader(readOracleFile(t, path))))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "pipelock verify-receipt") {
			t.Fatalf("expected failure for uninspected remainder, got %v", err)
		}
	})
}

func readOracleFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
