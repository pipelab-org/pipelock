// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// findStartRows are finds whose own arguments name . or PATH, which the
// shell does not run, and words outside those arguments that may change
// what find runs.
var findStartRows = []verdictRow{
	// Allowed: the words are find's starting points and tests.
	{"dot", "find . -type f -perm 0777 | xargs chmod 644", "", ""},
	{"dot, one test", "find . -perm 0777 | xargs chmod 644", "", ""},
	{"starting point naming path", "find ./mypath -perm 0777 | xargs chmod 644", "", ""},
	{"dot and a dir", "find . /srv -perm 0777 | xargs chmod 644", "", ""},
	{"name local", "find . -name local -perm 0777 | xargs chmod 644", "", ""},
	{"wholename test", "find . -wholename ./a/path -perm 1 | xargs chmod 644", "", ""},
	{"ipath test", "find /srv -ipath '*PATH*' -perm 0777 | xargs chmod 644", "", ""},
	{"name find", "find . -name find -perm 0777 | xargs chmod 644", "", ""},
	{"after another command", "cd /srv && find . -perm 0777 | xargs chmod 644", "", ""},

	// Still checked: the word is outside find's arguments.
	{"dot sourced first", ". ./x; find . -perm 777 | xargs chmod -R", incompletePairCheckRule, rulePermissions},
	{"dot sourced after a find", "find . -perm 1; . ./x; find . -perm 777 | xargs chmod -R", incompletePairCheckRule, rulePermissions},
	{"PATH after env", "env PATH=/tmp find . -perm 777 | xargs chmod -R", incompletePairCheckRule, rulePermissions},
	{"PATH after a find", "find . -perm 1 && PATH=/tmp find . -perm 777 | xargs chmod -R", incompletePairCheckRule, rulePermissions},
	{"eval after command", "command eval x; find . -perm 777 | xargs chmod -R", incompletePairCheckRule, rulePermissions},
	{"source after a pipe", "find . -perm 1 | source ./x; find . -perm 777 | xargs chmod -R", incompletePairCheckRule, rulePermissions},
	{"find not first", "env find . -perm 777 | xargs chmod -R", incompletePairCheckRule, rulePermissions},
	{"starting point printed", "find . 777 -type f | xargs chmod -R", incompletePairCheckRule, rulePermissions},
	{"find as an argument", "find . -name a; cat find -perm 0777 -name -R | xargs chmod 777", incompletePairCheckRule, rulePermissions},
}

// TestDefaultRules_FindStartingPoints checks findStartRows with the default
// rules.
func TestDefaultRules_FindStartingPoints(t *testing.T) {
	runVerdictRows(t, findStartRows)
}

// TestStrictPreset_FindStartingPoints checks findStartRows as a tools/call
// request under configs/strict.yaml: allowed rows pass, and checked rows are
// blocked as incomplete.
func TestStrictPreset_FindStartingPoints(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "configs", "strict.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	pc := New(cfg.MCPToolPolicy)
	if pc == nil {
		t.Fatal("strict tool policy is disabled")
	}
	for _, tt := range findStartRows {
		t.Run(tt.name, func(t *testing.T) {
			line, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": "tools/call",
				"params": map[string]any{"name": "run_command", "arguments": map[string]string{"command": tt.cmd}},
			})
			if err != nil {
				t.Fatal(err)
			}
			v := pc.CheckRequest(line)
			if tt.want == "" {
				if v.Matched || len(v.IncompleteRules) > 0 {
					t.Fatalf("verdict %q %v %v, want none", v.Action, v.Rules, v.IncompleteRules)
				}
				return
			}
			if !slices.Contains(v.Rules, incompletePairCheckRule) || v.Action != config.ActionBlock ||
				!slices.Contains(v.IncompleteRules, tt.inc) {
				t.Fatalf("verdict %q %v %v, want block for %s", v.Action, v.Rules, v.IncompleteRules, tt.inc)
			}
		})
	}
}

// TestFindPathsOnly_StartingPoints checks the words kept when . or PATH is
// one of find's arguments, and when it is not.
func TestFindPathsOnly_StartingPoints(t *testing.T) {
	tests := []struct {
		cmd, want string
	}{
		{"find . -perm 1 | xargs chmod", "find . | xargs chmod"},
		{"find ./mypath -path ./mypath/x -perm 1", "find ./mypath"},
		{"find . -name local -name set ; ls", "find . ; ls"},
		{"find . -perm 1 ; . x ; find . -perm 1", "find . -perm 1 ; . x ; find . -perm 1"},
		{"env PATH=/x find . -perm 1", "env PATH=/x find . -perm 1"},
		{"ls -path ; find . -perm 1", "ls -path ; find . -perm 1"},
		{"find . -perm 1 -ls;source x", "find . -perm 1 -ls;source x"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			got := findPathsOnly([][]string{strings.Fields(tt.cmd)})
			if want := [][]string{strings.Fields(tt.want)}; !slices.EqualFunc(got, want, slices.Equal[[]string]) {
				t.Fatalf("findPathsOnly(%q) = %q, want %q", tt.cmd, got, want)
			}
		})
	}
}
