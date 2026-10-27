// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"encoding/json"
	"fmt"
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

func TestDecide_ToolPolicyLongArgumentLists(t *testing.T) {
	files := make([]string, 70)
	crowd := make([]string, 70)
	for i := range files {
		files[i] = fmt.Sprintf("./build/obj_%d.o", i)
		crowd[i] = fmt.Sprintf("rm-%d", i)
	}
	jsonList := func(words []string) string {
		b, err := json.Marshal(words)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	tests := []struct {
		name     string
		input    string
		block    bool // on_incomplete_check: block
		want     Outcome
		evidence string
	}{
		{"args array past 64", `{"command":"rm","args":` + jsonList(append(files, "-rf", "/srv/data")) + `}`, false, Deny, "Destructive File Delete"},
		{"args array, flag first", `{"args":` + jsonList(append(append([]string{"-rf"}, crowd[:1]...), files...)) + `,"command":"rm"}`, false, Deny, "Destructive File Delete"},
		{"incomplete, default", `{"command":` + strconv.Quote(strings.Join(crowd, " ")) + `}`, false, Allow, "incomplete_pair_check"},
		{"incomplete, block", `{"command":` + strconv.Quote(strings.Join(crowd, " ")) + `}`, true, Deny, "incomplete_pair_check"},
		{"long listing", `{"command":` + strconv.Quote("ls "+strings.Join(files, " ")) + `}`, true, Allow, ""},
	}
	for _, tt := range tests {
		cfg, sc, _ := testSetup(t)
		if tt.block {
			cfg.MCPToolPolicy.OnIncompleteCheck = config.ActionBlock
		}
		pc := policy.New(cfg.MCPToolPolicy)
		paths := map[string]Decision{
			"mcp":      decideMCP(cfg, sc, pc, &MCPPayload{ToolName: "bash", ToolInput: tt.input}),
			"tool use": decideToolUse(cfg, sc, pc, &ToolUsePayload{ToolName: "bash", ToolInput: tt.input}),
		}
		for path, d := range paths {
			t.Run(tt.name+"/"+path, func(t *testing.T) {
				if d.Outcome != tt.want {
					t.Fatalf("outcome %s, want %s (evidence %+v)", d.Outcome, tt.want, d.Evidence)
				}
				if tt.evidence == "" {
					if len(d.Evidence) != 0 {
						t.Fatalf("unexpected evidence %+v", d.Evidence)
					}
					return
				}
				if !evidenceContainsPattern(d.Evidence, tt.evidence) {
					t.Fatalf("evidence %+v lacks %s", d.Evidence, tt.evidence)
				}
				line := IncompleteCheckLine(d)
				if tt.evidence != policy.IncompletePairCheckRule {
					if line != "" {
						t.Fatalf("unexpected incomplete line %q", line)
					}
					return
				}
				if !strings.HasPrefix(line, "pipelock: incomplete_pair_check (") || !strings.Contains(line, "rules=Destructive File Delete") {
					t.Fatalf("incomplete line %q lacks the rule names", line)
				}
			})
		}
	}
}

func TestDecide_XargsInputBoundary(t *testing.T) {
	for _, block := range []bool{false, true} {
		for _, safe := range []bool{false, true} {
			cfg, sc, _ := testSetup(t)
			cfg.MCPToolPolicy.OnIncompleteCheck = config.ActionWarn
			if block {
				cfg.MCPToolPolicy.OnIncompleteCheck = config.ActionBlock
			}
			command := "find . -type f | xargs chmod 777"
			if safe {
				command = "find . -type f -print0 | xargs -0 chmod 777"
			}
			input := `{"command":` + strconv.Quote(command) + `}`
			pc := policy.New(cfg.MCPToolPolicy)
			for name, d := range map[string]Decision{
				"mcp":  decideMCP(cfg, sc, pc, &MCPPayload{ToolName: "bash", ToolInput: input}),
				"hook": decideToolUse(cfg, sc, pc, &ToolUsePayload{ToolName: "bash", ToolInput: input}),
			} {
				want := Allow
				if block && !safe {
					want = Deny
				}
				if d.Outcome != want || evidenceContainsPattern(d.Evidence, policy.IncompletePairCheckRule) == safe {
					t.Fatalf("%s block=%v safe=%v: %+v", name, block, safe, d)
				}
			}
		}
	}
}
