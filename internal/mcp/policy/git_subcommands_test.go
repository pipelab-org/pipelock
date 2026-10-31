// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestGitUnknownSubcommandPolicy checks that a Git subcommand other than a
// builtin receives the strictest covered builtin verdict when the command has
// a long option word that spells or abbreviates a destructive option, whatever
// source might define the alias, and that builtins keep their own verdicts.
func TestGitUnknownSubcommandPolicy(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct {
		command, rule string
	}{
		// Alias sources the command line shows.
		{"git -c alias.r=reset r --ha", ruleGit},
		{"git -c alias.R=reset r --ha", ruleGit},
		{"git -c alias.r=reset R --ha", ruleGit},
		{"git -c alias.r.command=reset r --ha", ruleGit},
		{"V=reset git --config-env=alias.r=V r --ha", ruleGit},
		{"V=reset git --config-env alias.r=V r --ha", ruleGit},
		{"GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.r GIT_CONFIG_VALUE_0=reset git r --ha", ruleGit},
		{"GIT_CONFIG_PARAMETERS=\"'alias.r=reset'\" git r --ha", ruleGit},
		{"git -c 'alias.a=-p b' -c alias.b=reset a --ha", ruleGit},
		{"git -c 'alias.a=-c alias.b=reset b' a --ha", ruleGit},
		{"git -c 'alias.a=reset --har' a", ruleGit},
		{`git -c 'alias.a="b\q"' -c alias.bq=reset a --ha`, ruleGit},
		{"git -c alias.r=reset '[r]' --ha", ruleGit},
		{"git -c alias.r=reset [r] --ha", ruleGit},
		{"git -c alias.Q=reset r --har", ruleGit},
		{"git -c 'alias.a=--paginate b' -c alias.b.command=reset a --ha", ruleGit},
		{"V=reset git -c 'alias.a=--config-env alias.b=V b' a --ha", ruleGit},
		{"git -c alias.a=reset -c alias.b=a b --har", ruleGit},
		{"git -c alias.a=b -c alias.b.unmodeled=reset a --har", ruleGit},
		{"git -c alias.push=status push --forc", ruleGit},
		{"(git -c alias.r.command=reset r --ha)", ruleGit},
		{`bash -c "git -c 'alias.a=-p b' -c alias.b=reset a --ha"`, ruleGit},
		// Aliases are not followed, so one that runs a benign builtin, or a
		// --config-env cycle that defines no alias, is not told apart.
		{"git -c alias.a=push -c alias.l=ls-files l '--for=%(path)'", ruleGit},
		{"git -c alias.a=push -c alias.L.command=ls-files L '--for=%(path)'", ruleGit},
		{"V=--config-env=alias.a=V git --config-env=alias.a=V a --ha", ruleGit},
		{"V=--config-env=alias.a=W W=--config-env=alias.b=V git --config-env=alias.a=V a --ha", ruleGit},
		{"V=--config-env=alias.a=V; git --config-env=alias.a=V a --ha", ruleGit},
		// Sources the command line does not show.
		{"git r --ha", ruleGit},
		{"git r --hard", ruleGit},
		{"git RESET --ha", ruleGit},
		{"git -c include.path=/tmp/aliases r --ha", ruleGit},
		{"git -c 'includeIf.gitdir:**.path=/tmp/aliases' r --ha", ruleGit},
		{"GIT_CONFIG_GLOBAL=/tmp/aliases git r --ha", ruleGit},
		{"GIT_CONFIG_SYSTEM=/tmp/aliases git r --ha", ruleGit},
		{"GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=include.path GIT_CONFIG_VALUE_0=/tmp/aliases git r --ha", ruleGit},
		{"git -C project r --ha", ruleGit},
		{"git --git-dir project/.git r --ha", ruleGit},
		{"git --git-dir=project/.git --work-tree=project r --ha", ruleGit},
		{"GIT_DIR=project/.git git r --ha", ruleGit},
		{"git -c 'alias.s=-c include.path=/tmp/aliases r' s --ha", ruleGit},
		{"git -c 'alias.r=!git -c include.path=/tmp/aliases r --ha HEAD' r", ruleGit},
		{`git -c 'alias.s=!f() { git -c include.path=/tmp/aliases r "$@"; }; f' s --ha`, ruleGit},
		{"git $COMMAND --ha", ruleGit},
		{"git -p r --ha", ruleGit},
		{`git -C "$(pwd)" r --ha`, ruleGit},
		{`git -C "$(dirname "$(pwd)")" r --ha`, ruleGit},
		{`git -C "(" r --ha`, ruleGit},
		{`git -c 'alias.s=!a; b' s --ha`, ruleGit},
		{"git x --for origin topic", ruleGit},
		{"git x origin topic --force", ruleGit},
		{"git x --forc notes", ruleFileDelete},
		// The alias definition may come from elsewhere on the line.
		{"export V='reset --har'; git --config-env=alias.r=V r", ruleGit},
		{"V='reset --har' git --config-env=alias.r=V r", ruleGit},
		{"V=--har; git r $V", ruleGit},
		{"V=--har git r", ruleGit},
		{"export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.r GIT_CONFIG_VALUE_0='reset --har'; git r", ruleGit},
		// A destructive prefix anywhere on a line with a non-builtin subcommand.
		{"git co topic && npm install --force", ruleGit},
		// Shell wrapping and separators.
		{"cd project && git r --ha", ruleGit},
		{"git status; git r --ha", ruleGit},
		{"git init project && git -C project config alias.r reset && git -C project r --ha", ruleGit},
		{"bash -c 'git r --ha'", ruleGit},
		{"sudo git r --ha", ruleGit},
		{"env GIT_DIR=project/.git git r --ha", ruleGit},
		{"(git r --ha)", ruleGit},
		// A shell alias's first word runs as a utility.
		{"git -c 'alias.x=!rm --rec' x project", ruleFileDelete},
		{"git -c 'alias.x=!rm' x --rec project", ruleFileDelete},
		// A personal alias with a flag that prefixes a destructive option.
		{"git -c alias.l=ls-files l --for=%(path)", ruleGit},
		{"git l --for=%(path)", ruleGit},
		// Builtins keep their verdicts.
		{"git reset --ha", ruleGit},
		{"git push --for origin topic", ruleGit},
		{"git clean --fo -d", ruleGit},
		{"git rm --fo notes", ruleFileDelete},
		{"git -c alias.reset=status reset --har", ruleGit},
		// Benign builtins.
		{"git fetch --force", ""},
		{"git add --force notes", ""},
		{"git ls-files --for=%(path)", ""},
		{"git -c alias.a=push ls-files --for=%(path)", ""},
		{"sudo git -c alias.a=push ls-files --for=%(path)", ""},
		{"git reset --soft HEAD", ""},
		{"git reset --sof HEAD", ""},
		{"git clean -n", ""},
		{"git push --tags", ""},
		{"git log --for=topic", ""},
		{"git -c alias.r=reset status", ""},
		{"git -c 'alias.x=reset --ha' status", ""},
		{"GIT_CONFIG_GLOBAL=/dev/null git fetch --force", ""},
		{"git -C project status --short", ""},
		{"git -c alias.r.command=status r --short", ""},
		{"cd project && git -c 'alias.a=-p b' -c alias.b=log a --format=%H", ""},
		{"git -c alias.r.command=reset r --sof HEAD", ""},
		{"git -c alias.p.command=push p --force-w origin main", ""},
		{`git -C "$(git rev-parse --show-toplevel)" fetch --force`, ""},
		{`git -c core.pager=cat -C "$(pwd)" fetch --force`, ""},
		{"git status && ls --for=x", ""},
		// Unknown subcommands without a destructive option word.
		{"git st", ""},
		{"git lg --oneline", ""},
		{"git lg --graph --format=%h", ""},
		{"git co -b topic", ""},
		// An alias run without any option word is not matched (same as before).
		{"git undo", ""},
	} {
		t.Run(tc.command, func(t *testing.T) {
			v := pc.CheckToolCall("bash", []string{tc.command})
			if tc.rule == "" {
				if v.Matched {
					t.Errorf("benign command matched %v", v.Rules)
				}
				return
			}
			if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, tc.rule) {
				t.Errorf("got %+v, want block by %s", v, tc.rule)
			}
		})
	}
	// Separate argv values are read the same way.
	for _, argv := range [][]string{
		{"git", "-c", "alias.r=reset", "r", "--ha"},
		{"git", "-c", "include.path=/tmp/aliases", "r", "--ha"},
		{"bash", "-c", "git -c 'alias.a=-c alias.b=reset b' a --ha"},
	} {
		if v := pc.CheckToolCall("bash", argv); !v.Matched || v.Action != config.ActionBlock {
			t.Errorf("%q: %+v", argv, v)
		}
	}
}

// TestGitDestructiveOptionsFromRules derives gitDestructiveOptions from the
// built-in rules: a covered Git subcommand's long option is destructive when
// a built-in blocking rule matches git <subcommand> --<option> on its own.
func TestGitDestructiveOptionsFromRules(t *testing.T) {
	var rules []*regexp.Regexp
	for _, rule := range DefaultToolPolicyRules() {
		if rule.Action == config.ActionBlock && regexp.MustCompile(rule.ToolPattern).MatchString("bash") {
			rules = append(rules, regexp.MustCompile(rule.ArgPattern))
		}
	}
	var derived []string
	for _, command := range []string{"reset", "clean", "push", "rm"} {
		key, ok := gitCommandKey(command)
		if !ok {
			t.Fatalf("%s is not a covered Git subcommand", command)
		}
		for _, option := range commandLongOptions[key].names {
			line := "git " + command + " --" + option
			if slices.ContainsFunc(rules, func(re *regexp.Regexp) bool { return re.MatchString(line) }) {
				derived = append(derived, command+" --"+option)
			}
		}
	}
	var table []string
	for _, d := range gitDestructiveOptions {
		table = append(table, d.command+" --"+d.option)
	}
	if !slices.Equal(derived, table) {
		t.Fatalf("rules make %q destructive, table lists %q", derived, table)
	}
}

func TestGitDestructiveReadings(t *testing.T) {
	for _, tc := range []struct {
		word string
		want []string
	}{
		{"--h", []string{"reset --hard"}},
		{"--hard", []string{"reset --hard"}},
		{"--f", []string{"push --force", "rm --force"}},
		{"--for=%(path)", []string{"push --force", "rm --force"}},
		{"--force", []string{"push --force", "rm --force"}},
		{"--format", nil},
		{"--forced", nil},
		{"--force-with-lease", nil},
		{"--HA", nil},
		{"--soft", nil},
		{"--", nil},
		{"--=x", nil},
		{"-f", nil},
		{"hard", nil},
	} {
		if got := gitDestructiveReadings(tc.word); !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.word, got, tc.want)
		}
	}
}

func TestGitBuiltinsList(t *testing.T) {
	// git --list-cmds=builtins printed 149 names for Git 2.56.0.
	if len(gitBuiltins) != 149 {
		t.Fatalf("%d builtins", len(gitBuiltins))
	}
	for _, name := range []string{"reset", "clean", "push", "rm", "fetch", "add", "ls-files", "status", "log"} {
		if !gitBuiltins[name] {
			t.Errorf("%s missing", name)
		}
	}
	for _, name := range []string{"RESET", "submodule", "lfs", "filter-branch", "st"} {
		if gitBuiltins[name] {
			t.Errorf("%s listed", name)
		}
	}
	for name := range gitBuiltins {
		if strings.ToLower(name) != name {
			t.Errorf("%s is not lowercase", name)
		}
	}
}

// TestGitToolUnknownSubcommandPolicy checks the dedicated git tool, whose
// arguments are Git's own argument list without the word git: a subcommand
// other than a builtin gets the strictest covered builtin verdict through the
// tool too, through every entry point, and builtins keep their verdicts.
func TestGitToolUnknownSubcommandPolicy(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct {
		tool  string
		args  []string
		block bool
	}{
		{"git", []string{"r --ha"}, true},
		{"git", []string{"r", "--ha"}, true},
		{"git", []string{"r --hard"}, true},
		{"git", []string{"-c alias.r=reset r --ha"}, true},
		{"git", []string{"-c", "alias.r=reset", "r", "--ha"}, true},
		{"git", []string{"-C /srv/repo r --ha"}, true},
		{"git", []string{"l --for=%(path)"}, true},
		{"git", []string{"p --forc origin main"}, true},
		{"git", []string{"git r --ha"}, true},
		// A git tool runs no shell, so a separator stays inside an argument.
		{"git", []string{"status; fetch --force"}, true},
		{"git", []string{`-C "$(pwd)" r --ha`}, true},
		{"GIT", []string{"r --ha"}, true},
		{"mcp__vcs__git", []string{"r --ha"}, true},
		{"vcs.git", []string{"r --ha"}, true},
		{"vcs:git", []string{"r --ha"}, true},
		{"git", []string{"reset --ha"}, true},
		{"git", []string{"push --for origin main"}, true},
		{"git", []string{"clean --fo -d"}, true},
		// Builtins keep their verdicts.
		{"git", []string{"fetch --force"}, false},
		{"git", []string{"fetch", "--force"}, false},
		{"git", []string{"add --force notes"}, false},
		{"git", []string{"ls-files --for=%(path)"}, false},
		{"git", []string{"reset --soft HEAD"}, false},
		{"git", []string{"reset --sof HEAD"}, false},
		{"git", []string{"-C /srv/repo fetch --force"}, false},
		{"git", []string{"-c alias.r=reset status --short"}, false},
		// Unknown subcommands without a destructive option word.
		{"git", []string{"st"}, false},
		{"git", []string{"lg --oneline"}, false},
		// Names the default rules don't treat as the git tool keep the
		// shell reading, where a bare word is not a Git subcommand.
		{"mcp__git__run", []string{"r --ha"}, false},
		{"git_status", []string{"r --ha"}, false},
		{"bash", []string{"r --ha"}, false},
	} {
		t.Run(tc.tool+" "+strings.Join(tc.args, " | "), func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"command": strings.Join(tc.args, " ")})
			if err != nil {
				t.Fatal(err)
			}
			line, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": "tools/call",
				"params": map[string]any{"name": tc.tool, "arguments": json.RawMessage(raw)},
			})
			if err != nil {
				t.Fatal(err)
			}
			command := strings.Join(tc.args, " ")
			verdicts := map[string]Verdict{
				"argv": pc.CheckToolCall(tc.tool, tc.args),
				"MCP":  pc.CheckRequest(line),
				"hook": pc.CheckToolCallJSON(tc.tool, []string{command}, []string{"command", command}, raw),
			}
			for name, v := range verdicts {
				blocked := v.Matched && v.Action == config.ActionBlock
				if blocked != tc.block {
					t.Errorf("%s: got %+v, want block=%v", name, v, tc.block)
				}
			}
		})
	}
}

// TestGitToolNameFromRules checks gitToolName against the default rules: a
// tool is the git tool when the Destructive Git Operation rule matches it and
// the shell tool rules (here Destructive File Delete) do not.
func TestGitToolNameFromRules(t *testing.T) {
	var gitRule, shellRule *regexp.Regexp
	for _, rule := range DefaultToolPolicyRules() {
		switch rule.Name {
		case "Destructive Git Operation":
			gitRule = regexp.MustCompile(rule.ToolPattern)
		case "Destructive File Delete":
			shellRule = regexp.MustCompile(rule.ToolPattern)
		}
	}
	if gitRule == nil || shellRule == nil {
		t.Fatal("default rules missing")
	}
	for _, name := range []string{
		"git", "GIT", "mcp__vcs__git", "mcp__git__git", "vcs.git", "vcs:git",
		"bash", "mcp__vcs__bash", "shell", "mcp__git__run", "git_status", "gitx",
		"xgit", "mcp__a__b__git", "a.b.git", "git.bash", "run_command", "",
	} {
		want := gitRule.MatchString(name) && !shellRule.MatchString(name)
		if got := gitToolName.MatchString(name); got != want {
			t.Errorf("%q: gitToolName %v, rules %v", name, got, want)
		}
	}
}
