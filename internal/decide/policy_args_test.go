// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
)

// TestDecide_ToolPolicyMatchesArgumentValues checks that a command reaches the
// tool policy as the same text whether it arrives as a shell command or as
// the "command" value of MCP or tool-use input, so the object key does not
// move a 64-value command over the pairwise cap. Object keys are still
// matched for MCP and tool-use input.
func TestDecide_ToolPolicyMatchesArgumentValues(t *testing.T) {
	cfg, sc, _ := testSetup(t)
	const (
		anchored = "Anchored Command"
		paired   = "Paired Flag"
		keyText  = "Key Text"
	)
	pc := policy.New(config.MCPToolPolicy{
		Enabled: true,
		Action:  config.ActionBlock,
		Rules: []config.ToolPolicyRule{
			{Name: anchored, ToolPattern: `^bash$`, ArgPattern: `^rm -rf /srv/data$`, Action: config.ActionBlock},
			{Name: paired, ToolPattern: `^bash$`, ArgPattern: `^rm -rf$`, Action: config.ActionBlock},
			{Name: keyText, ToolPattern: `^bash$`, ArgPattern: `^command$`, Action: config.ActionBlock},
		},
	})

	// 64 tokens: every ordered pair is still checked. A 65th token from the
	// object key would move the list onto the bounded pair scan, where 64
	// distinct short tokens use up the pair checks before "-rf" is paired.
	words := make([]string, 62)
	for i := range words {
		words[i] = "w" + strconv.Itoa(i)
	}
	atCap := "rm " + strings.Join(words, " ") + " -rf"
	if n := len(strings.Fields(atCap)); n != 64 {
		t.Fatalf("command has %d tokens, want 64", n)
	}

	tests := []struct {
		name    string
		command string
		want    map[string]bool
	}{
		{"anchored command", "rm -rf /srv/data", map[string]bool{anchored: true, paired: true}},
		{"command at the pairwise cap", atCap, map[string]bool{paired: true}},
		{"plain command", "ls -la", map[string]bool{}},
	}
	for _, tt := range tests {
		input := `{"command":` + strconv.Quote(tt.command) + `}`
		paths := map[string]Decision{
			"shell":    decideShell(cfg, sc, pc, &ShellPayload{Command: tt.command}),
			"mcp":      decideMCP(cfg, sc, pc, &MCPPayload{ToolName: "bash", ToolInput: input}),
			"tool use": decideToolUse(cfg, sc, pc, &ToolUsePayload{ToolName: "bash", ToolInput: input}),
		}
		for path, d := range paths {
			t.Run(tt.name+"/"+path, func(t *testing.T) {
				for _, rule := range []string{anchored, paired, keyText} {
					want := tt.want[rule] || (rule == keyText && path != "shell")
					if got := evidenceContainsPattern(d.Evidence, rule); got != want {
						t.Errorf("rule %q matched=%v, want %v (evidence %+v)", rule, got, want, d.Evidence)
					}
				}
			})
		}
	}
}

// TestDecide_ToolPolicyMatchesArgumentKeys checks that text sent as an object
// key still reaches the tool policy on the MCP and tool-use paths.
func TestDecide_ToolPolicyMatchesArgumentKeys(t *testing.T) {
	cfg, sc, pc := testSetup(t)
	tests := []struct {
		name  string
		input string
		want  Outcome
	}{
		{"command as key", `{"rm -rf /srv/data":""}`, Deny},
		{"command as value", `{"command":"rm -rf /srv/data"}`, Deny},
		{"plain key", `{"ls -la":""}`, Allow},
	}
	for _, tt := range tests {
		paths := map[string]Decision{
			"mcp":      decideMCP(cfg, sc, pc, &MCPPayload{ToolName: "bash", ToolInput: tt.input}),
			"tool use": decideToolUse(cfg, sc, pc, &ToolUsePayload{ToolName: "bash", ToolInput: tt.input}),
		}
		for path, d := range paths {
			t.Run(tt.name+"/"+path, func(t *testing.T) {
				if d.Outcome != tt.want {
					t.Fatalf("outcome %s, want %s (evidence %+v)", d.Outcome, tt.want, d.Evidence)
				}
				if tt.want == Deny && !evidenceContainsPattern(d.Evidence, "Destructive File Delete") {
					t.Fatalf("evidence %+v lacks Destructive File Delete", d.Evidence)
				}
			})
		}
	}
}
