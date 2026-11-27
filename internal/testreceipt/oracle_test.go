// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package testreceipt

import (
	"maps"
	"slices"
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
