// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	ruleGitHook   = "Git Hook Bypass"
	ruleGitBranch = "Unmerged Git Branch Delete"
)

// destructiveGitSurfaces are the three ways a shell command is submitted.
func destructiveGitSurfaces(t *testing.T, pc *Config, command string) map[string]Verdict {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "bash", "arguments": json.RawMessage(raw)},
	})
	if err != nil {
		t.Fatal(err)
	}
	values, truncated := ArgValues(raw)
	if truncated {
		t.Fatal("truncated")
	}
	return map[string]Verdict{
		"CheckToolCall":     pc.CheckToolCall("bash", []string{command}),
		"CheckRequest":      pc.CheckRequest(line),
		"CheckToolCallJSON": pc.CheckToolCallJSON("bash", values, append([]string{"command"}, values...), raw),
	}
}

func wantGitRule(t *testing.T, v Verdict, command, surface, rule, action string, absent ...string) {
	t.Helper()
	if !v.Matched || v.Action != action || !slices.Contains(v.Rules, rule) {
		t.Errorf("%s %q: got matched=%v action=%q rules=%v, want %s %s", surface, command, v.Matched, v.Action, v.Rules, action, rule)
	}
	for _, name := range absent {
		if slices.Contains(v.Rules, name) {
			t.Errorf("%s %q: rule %s also matched (%v)", surface, command, name, v.Rules)
		}
	}
}

// origin/main matched only push --force, reset --hard, and clean -fd.
// These spellings must not match that pattern. The prior list keeps it, so a
// form listed here has to stay out of every prior too.
const originMainDestructiveGitPattern = `(?i)(?:^|[\s;|&()<>\x60\x22\x27/=])(git\s+)?(push(?:\s+[^\s;|&]+)*?\s+(--force(?:[\s;&|()<>]|$)|-[a-z]*f[a-z]*\b|\+[^\s;|&]+)|reset(?:\s+[^\s;|&]+)*?\s+--hard\b|clean(?:\s+[^\s;|&]+)*?\s+(-[a-z]*(f[a-z]*d|d[a-z]*f)[a-z]*\b|-[a-z]*f[a-z]*(?:\s+[^\s;|&]+)*?\s+-[a-z]*d[a-z]*\b|-[a-z]*d[a-z]*(?:\s+[^\s;|&]+)*?\s+-[a-z]*f[a-z]*\b))`

func TestDestructiveGitBlockForms(t *testing.T) {
	pc := defaultConfig(t)
	previous := regexp.MustCompile(originMainDestructiveGitPattern)
	commands := []string{
		"git reset --hard",
		"git reset --hard HEAD",
		"git clean -fd",
		"git clean -df",
		"git push --force",
		"git push -f origin main",
		"git push origin +main",
		"git checkout -f",
		"git checkout --force other",
		"git checkout -B feature",
		"git checkout -Bfeature origin/main",
		"git checkout ./.",
		"git checkout ./. ",
		"git checkout -- ./.",
		"git checkout HEAD -- :/",
		"git checkout :/",
		"git checkout -- :/",
		"git checkout ':(top)'",
		"git switch -f other",
		"git switch --force other",
		"git switch --discard-changes other",
		"git switch -C feature",
		"git switch --force-create feature",
		"git branch -f feature HEAD",
		"git branch --force feature HEAD",
		"git branch -M old new",
		"git branch -C old new",
		"git branch --move --force old new",
		"git restore ./.",
		"git restore :/",
		"git restore -- :/",
		"git restore --worktree :/",
		"git restore --worktree ./.",
		"git restore --source HEAD :/",
		"git restore --source=HEAD :/",
		"git restore --staged --worktree :/",
		"git restore -W :/",
		"GIT CHECKOUT :/",
		"Git Checkout --Force other",
		"bash -c \"echo ready; git checkout :/\"",
		"bash -c 'git reset --hard'",
		"xargs git clean -fd",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			if previous.MatchString(command) && !strings.Contains(command, "reset --hard") &&
				!strings.Contains(command, "clean -fd") && !strings.Contains(command, "clean -df") &&
				!strings.Contains(command, "push --force") &&
				!strings.Contains(command, "push -f") && !strings.Contains(command, "+main") {
				t.Fatalf("origin/main pattern already matched %q", command)
			}
			for surface, v := range destructiveGitSurfaces(t, pc, command) {
				wantGitRule(t, v, command, surface, ruleGit, config.ActionBlock)
			}
		})
	}
	// The git tool submits Git's argument list without the word git.
	v := pc.CheckToolCall("git", []string{"checkout", ":/"})
	wantGitRule(t, v, "git checkout :/", "git tool", ruleGit, config.ActionBlock)
}

func TestGitHookBypassWarns(t *testing.T) {
	pc := defaultConfig(t)
	commands := []string{
		"git commit --no-verify -m msg",
		"git commit -n -m msg",
		"git commit -n",
		"git am --no-verify mailbox",
		"git am -n mailbox",
		"git merge --no-verify topic",
		"git rebase --no-verify origin/main",
		"git push --no-verify origin main",
		"git -c core.hooksPath=/dev/null status",
		"git -c core.hooksPath=/dev/null commit -m msg",
		"git config core.hooksPath /dev/null",
		"git config --local core.hooksPath ./githooks",
		"git config core.hooksPath=githooks",
		"GIT COMMIT --no-verify -m msg",
		"bash -c \"git commit --no-verify -m msg\"",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			for surface, v := range destructiveGitSurfaces(t, pc, command) {
				wantGitRule(t, v, command, surface, ruleGitHook, config.ActionWarn, ruleGit)
			}
		})
	}
	// Force plus a hook skip stays a block. Both rules are reported.
	for surface, v := range destructiveGitSurfaces(t, pc, "git push --force --no-verify") {
		wantGitRule(t, v, "git push --force --no-verify", surface, ruleGit, config.ActionBlock)
		if !slices.Contains(v.Rules, ruleGitHook) {
			t.Errorf("%s: hook rule missing from %v", surface, v.Rules)
		}
	}
}

func TestUnmergedBranchDeleteWarns(t *testing.T) {
	pc := defaultConfig(t)
	warns := []string{
		"git branch -D feature",
		"git branch -D feature other",
		"GIT BRANCH -D feature",
		"bash -c \"git branch -D feature\"",
	}
	for _, command := range warns {
		t.Run(command, func(t *testing.T) {
			for surface, v := range destructiveGitSurfaces(t, pc, command) {
				wantGitRule(t, v, command, surface, ruleGitBranch, config.ActionWarn, ruleGit)
			}
		})
	}
	// -d -f and --delete --force are the same operation as -D, but they also
	// carry the force flag the block rule matches. Block wins.
	for _, command := range []string{
		"git branch -d -f feature",
		"git branch -f -d feature",
		"git branch -fd feature",
		"git branch --delete --force feature",
		"git branch --force --delete feature",
	} {
		t.Run(command, func(t *testing.T) {
			for surface, v := range destructiveGitSurfaces(t, pc, command) {
				wantGitRule(t, v, command, surface, ruleGit, config.ActionBlock)
				if !slices.Contains(v.Rules, ruleGitBranch) {
					t.Errorf("%s: delete rule missing from %v", surface, v.Rules)
				}
			}
		})
	}
	v := pc.CheckToolCall("git", []string{"branch", "-D", "feature"})
	wantGitRule(t, v, "branch -D", "git tool", ruleGitBranch, config.ActionWarn, ruleGit)
}

func TestDestructiveGitSelfUndoAllowed(t *testing.T) {
	pc := defaultConfig(t)
	commands := []string{
		"git checkout -- file.go",
		"git checkout -- src/file.go",
		"git checkout file.go",
		"git checkout src/a.go",
		"git checkout HEAD -- file.go",
		"git checkout main -- src/main.go",
		"git checkout -- src",
		"git checkout .",
		"git checkout -- .",
		"git checkout HEAD -- .",
		"git restore .",
		"git restore -- .",
		"git restore --worktree .",
		"git restore --source HEAD .",
		"git restore file.go",
		"git restore src/file.go",
		"git restore src",
		"git restore src/",
		"git restore --worktree file.go",
		"git restore --source HEAD -- file.go",
		"git restore --source=HEAD file.go",
		"git restore --staged file.go",
		"git restore --staged .",
		"git restore -S file.go",
		"git restore -S .",
		"git checkout -b feature",
		"git checkout main",
		"git switch -c feature",
		"git switch main",
		"git branch -d merged",
		"git branch --delete merged",
		"git branch -m old new",
		"git branch -c old new",
		"git push --force-with-lease origin main",
		"git push --force-with-lease=refs/heads/main origin main",
		"git push --force-if-includes --force-with-lease origin main",
		"git commit --no-verbose -m msg",
		"git commit --amend --no-edit",
		"git merge -n topic",
		"git rebase -n origin/main",
		"git rebase --force-rebase",
		"git fetch --force",
		"git config --get core.hooksPath",
		"git config core.hooksPath",
		"git config --unset core.hooksPath",
		"git config --get-regexp core.hooksPath",
		"git restore",
		"git restore --source=HEAD",
		"git push origin main",
		"bash -c \"git checkout -- file.go\"",
		"bash -c \"git restore --staged file.go\"",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			for surface, v := range destructiveGitSurfaces(t, pc, command) {
				if v.Matched && (slices.Contains(v.Rules, ruleGit) || slices.Contains(v.Rules, ruleGitHook) || slices.Contains(v.Rules, ruleGitBranch)) {
					t.Errorf("%s %q: got %q %v", surface, command, v.Action, v.Rules)
				}
			}
		})
	}
}

func TestBenignGitCommandsDoNotBlock(t *testing.T) {
	pc := defaultConfig(t)
	f, err := os.Open(filepath.Join("testdata", "benign_git_commands.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	n := 0
	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())
		if command == "" || strings.HasPrefix(command, "#") {
			continue
		}
		n++
		v := pc.CheckToolCall("bash", []string{command})
		if slices.Contains(v.Rules, ruleGit) {
			t.Errorf("block rule matched %q: %v", command, v.Rules)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 229 {
		t.Fatalf("benign corpus has %d commands, want at least 229", n)
	}
}

func TestGitFormPresetActions(t *testing.T) {
	presets := []struct {
		path        string
		destructive string
		hook        string
		branch      string
	}{
		{"../../../configs/claude-code.yaml", config.ActionBlock, config.ActionWarn, config.ActionWarn},
		{"../../../configs/cursor.yaml", config.ActionBlock, config.ActionWarn, config.ActionWarn},
		{"../../../configs/balanced.yaml", config.ActionBlock, config.ActionWarn, config.ActionWarn},
		{"../../../configs/generic-agent.yaml", config.ActionWarn, config.ActionWarn, config.ActionWarn},
		{"../../../configs/audit.yaml", config.ActionBlock, config.ActionWarn, config.ActionWarn},
		{"../../../configs/strict.yaml", config.ActionBlock, config.ActionBlock, config.ActionWarn},
		{"../../../configs/hostile-model.yaml", config.ActionBlock, config.ActionBlock, config.ActionWarn},
		{"../../../examples/quickstart/pipelock.yaml", config.ActionBlock, config.ActionWarn, config.ActionWarn},
	}
	for _, preset := range presets {
		t.Run(filepath.Base(preset.path), func(t *testing.T) {
			cfg, err := config.Load(preset.path)
			if err != nil {
				t.Fatal(err)
			}
			pc := New(cfg.MCPToolPolicy)
			if pc == nil {
				t.Fatal("nil policy")
			}
			checks := []struct {
				command, rule, action string
			}{
				{"git reset --hard", ruleGit, preset.destructive},
				{"git checkout :/", ruleGit, preset.destructive},
				{"git commit --no-verify -m msg", ruleGitHook, preset.hook},
				{"git branch -D feature", ruleGitBranch, preset.branch},
			}
			for _, check := range checks {
				v := pc.CheckToolCall("bash", []string{check.command})
				wantGitRule(t, v, check.command, filepath.Base(preset.path), check.rule, check.action)
			}
		})
	}
}

func TestPresetGitFormPatternsMatchDefaults(t *testing.T) {
	want := map[string]string{
		ruleGit:       destructiveGitArgPattern,
		ruleGitHook:   gitHookBypassArgPattern,
		ruleGitBranch: gitUnmergedBranchDeleteArgPattern,
	}
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "configs", "*.yaml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no presets: %v", err)
	}
	paths = append(paths, filepath.Join("..", "..", "..", "examples", "quickstart", "pipelock.yaml"))
	for _, path := range paths {
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		seen := map[string]bool{}
		for _, rule := range cfg.MCPToolPolicy.Rules {
			pattern, ok := want[rule.Name]
			if !ok {
				continue
			}
			seen[rule.Name] = true
			if rule.ArgPattern != pattern {
				t.Errorf("%s: %q arg_pattern differs from the built-in default", filepath.Base(path), rule.Name)
			}
		}
		if len(seen) != len(want) {
			t.Errorf("%s: carries %d of %d git form rules", filepath.Base(path), len(seen), len(want))
		}
	}
}
