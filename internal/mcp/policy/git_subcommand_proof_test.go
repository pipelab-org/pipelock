// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// gitCarrier is one way a request submits a Git command: a shell command
// string or argument list to a shell tool, or a string or argument list to the
// git tool.
type gitCarrier string

const (
	bashString gitCarrier = "bash string"
	bashArgv   gitCarrier = "bash argv"
	gitString  gitCarrier = "git string"
	gitArgv    gitCarrier = "git argv"
)

var gitCarriers = []gitCarrier{bashString, bashArgv, gitString, gitArgv}

// gitCarrierArgs submits words, Git's arguments after the executable, through
// carrier. A string carrier joins them with spaces.
func gitCarrierArgs(carrier gitCarrier, words []string) (tool string, args []string, key string) {
	switch carrier {
	case bashString:
		return "bash", []string{"git " + strings.Join(words, " ")}, "command"
	case bashArgv:
		return "bash", append([]string{"git"}, words...), "argv"
	case gitString:
		return "git", []string{strings.Join(words, " ")}, "command"
	default:
		return "git", words, "argv"
	}
}

// gitProofVerdicts checks one submission through CheckToolCall, CheckRequest
// and CheckToolCallJSON, with the JSON shape a string or argument list has.
func gitProofVerdicts(t *testing.T, pc *Config, tool string, args []string, key string) map[string]Verdict {
	t.Helper()
	var value any = args
	if key == "command" {
		value = args[0]
	}
	raw, err := json.Marshal(map[string]any{key: value})
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": json.RawMessage(raw)},
	})
	if err != nil {
		t.Fatal(err)
	}
	values, truncated := ArgValues(raw)
	if truncated {
		t.Fatal("truncated")
	}
	return map[string]Verdict{
		"CheckToolCall":     pc.CheckToolCall(tool, args),
		"CheckRequest":      pc.CheckRequest(line),
		"CheckToolCallJSON": pc.CheckToolCallJSON(tool, values, append([]string{key}, values...), raw),
	}
}

// TestGitSubcommandProof checks when a Git subcommand keeps its builtin
// reading. Each row is Git's arguments after the executable, submitted through
// every carrier. allow names the carriers on which Git, as the request is
// read, runs a builtin with these arguments and policy allows; every other
// carrier blocks, because Git runs an alias or git-<name> program with the
// destructive option, or because the request does not show which subcommand
// runs.
func TestGitSubcommandProof(t *testing.T) {
	all := gitCarriers
	for _, tc := range []struct {
		name  string
		words []string
		allow []gitCarrier
	}{
		// Builtins with a destructive-looking option stay allowed.
		{"plain fetch", []string{"fetch", "--force"}, all},
		{"plain add", []string{"add", "--force", "notes"}, all},
		{"plain checkout", []string{"checkout", "--force", "main"}, all},
		{"plain global flag", []string{"--no-pager", "fetch", "--force"}, all},
		{"plain -C", []string{"-C", "/srv/repo", "fetch", "--force"}, all},
		{"plain -c", []string{"-c", "core.pager=cat", "fetch", "--force"}, all},
		{"plain attached value", []string{"--git-dir=/srv/repo/.git", "fetch", "--force"}, all},
		{"unicode operand", []string{"add", "--force", "caf\u00e9.txt"}, all},
		{"quoted operand", []string{"fetch", "--force", "'origin'", `"main"`}, []gitCarrier{bashString, bashArgv, gitString, gitArgv}},
		{"commit message", []string{"commit", "-m", "'fix: \u00fcber --force note'"}, all},
		// Unknown subcommands (round-3 shapes).
		{"r3 bare", []string{"r", "--ha"}, nil},
		{"r3 inline alias", []string{"-c", "alias.r=reset", "r", "--ha"}, nil},
		{"r3 -C", []string{"-C", "/srv/repo", "r", "--ha"}, nil},
		{"r3 --git-dir", []string{"--git-dir", "/srv/repo/.git", "r", "--ha"}, nil},
		{"r3 format", []string{"l", "--for=%(path)"}, nil},
		// Lookalike and invisible spellings (round 4).
		{"zero width", []string{"fet\u200bch", "--force"}, nil},
		{"cyrillic", []string{"f\u0435tch", "--force"}, nil},
		{"carriage return", []string{"fetch\r", "--force"}, nil},
		{"fullwidth", []string{"\uff46etch", "--force"}, nil},
		{"add zero width", []string{"a\u200bdd", "--force"}, nil},
		{"vertical tab", []string{"fetch\v", "--force"}, nil},
		{"form feed", []string{"fetch\f", "--force"}, nil},
		{"no-break space", []string{"fetch\u00a0x", "--force"}, nil},
		{"embedded newline", []string{"fe\ntch", "--force"}, nil},
		// Escapes and quotes (round 5). The shell runs builtin fetch for the
		// unquoted backslash, empty quotes, both quote forms and ANSI-C
		// quoting; those spellings block by design.
		{"hex unquoted", []string{`fe\x74ch`, "--force"}, nil},
		{"hex single", []string{`'fe\x74ch'`, "--force"}, nil},
		{"hex double", []string{`"fe\x74ch"`, "--force"}, nil},
		{"backslash unquoted", []string{`fe\tch`, "--force"}, nil},
		{"backslash single", []string{`'fe\tch'`, "--force"}, nil},
		{"backslash double", []string{`"fe\tch"`, "--force"}, nil},
		{"empty quotes", []string{"f''etch", "--force"}, nil},
		{"single quotes", []string{"'fetch'", "--force"}, nil},
		{"double quotes", []string{`"fetch"`, "--force"}, nil},
		{"ansi-c", []string{"$'fetch'", "--force"}, nil},
		{"ansi-c hex", []string{`$'fe\x74ch'`, "--force"}, nil},
		{"continuation", []string{"fe\\\ntch", "--force"}, nil},
		{"ansi-c unicode", []string{`$'\u0066etch'`, "--force"}, nil},
		{"ansi-c unicode e", []string{`$'f\u0065tch'`, "--force"}, nil},
		{"variable", []string{"$SUB", "--force"}, nil},
		// The executable word is a subcommand once git has been read.
		{"git as subcommand", []string{"git", "--force"}, nil},
		{"path git as subcommand", []string{"/usr/bin/git", "--force"}, nil},
		{"relative git as subcommand", []string{"./git", "--force"}, nil},
		{"git then builtin", []string{"git", "fetch", "--force"}, nil},
		// Unrecognized global syntax does not skip to a later word.
		{"unknown global option", []string{"-X", "fetch", "--force"}, nil},
		{"exiting global option", []string{"--version", "fetch", "--force"}, nil},
	} {
		for _, carrier := range all {
			want := !slices.Contains(tc.allow, carrier)
			checkGitProofRow(t, tc.name, carrier, tc.words, want)
		}
	}
	// Argument boundaries that differ between a shell string and an argument
	// list: quoted global values and a subcommand with a space.
	for _, tc := range []struct {
		name  string
		words []string
	}{
		{"quoted -C value", []string{"-C", "'a fetch b'", "rogue", "--force"}},
		{"quoted -c value", []string{"-c", "'x.y=a fetch b'", "rogue", "--force"}},
		{"quoted subcommand with space", []string{"'fetch x'", "--force"}},
	} {
		for _, carrier := range all {
			checkGitProofRow(t, tc.name, carrier, tc.words, true)
		}
	}
	for _, tc := range []struct {
		name  string
		words []string
	}{
		{"-C value with space", []string{"-C", "a fetch b", "rogue", "--force"}},
		{"-c value with space", []string{"-c", "x.y=a fetch b", "rogue", "--force"}},
		{"subcommand with space", []string{"fetch x", "--force"}},
	} {
		for _, carrier := range []gitCarrier{bashArgv, gitArgv} {
			checkGitProofRow(t, tc.name, carrier, tc.words, true)
		}
	}
	// The same words in a string are separate arguments: Git runs builtin fetch
	// with an operand x.
	for _, carrier := range []gitCarrier{bashString, gitString} {
		checkGitProofRow(t, "string fetch x", carrier, []string{"fetch x", "--force"}, false)
	}
}

func checkGitProofRow(t *testing.T, name string, carrier gitCarrier, words []string, block bool) {
	t.Helper()
	for _, mode := range []string{config.ActionWarn, config.ActionBlock} {
		pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, OnIncompleteCheck: mode, Rules: DefaultToolPolicyRules()})
		tool, args, key := gitCarrierArgs(carrier, words)
		t.Run(name+"/"+string(carrier)+"/"+mode+"/"+strconv.Quote(strings.Join(words, " ")), func(t *testing.T) {
			for entry, v := range gitProofVerdicts(t, pc, tool, args, key) {
				if blocked := v.Matched && v.Action == config.ActionBlock; blocked != block {
					t.Errorf("%s: got %+v, want block=%v", entry, v, block)
				}
			}
		})
	}
}

// TestGitSubcommandProofShape checks that the git tool's argument list is read
// from the request's JSON shape, not guessed from the number of values.
func TestGitSubcommandProofShape(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct {
		name, arguments string
		block           bool
	}{
		// One string: its plain words are the arguments.
		{"string", `{"command":"fetch --force"}`, false},
		// One element: Git runs the whole element as the subcommand.
		{"one element", `{"argv":["fetch --force"]}`, true},
		{"one element then option", `{"argv":["fetch x","--force"]}`, true},
		{"argument list", `{"argv":["fetch","--force"]}`, false},
		{"nested argument list", `{"input":{"argv":["fetch","--force"]}}`, false},
		// Values in more than one place have no recorded order or grammar.
		{"two strings", `{"subcommand":"fetch","flags":"--force"}`, true},
		{"list and string", `{"argv":["fetch","--force"],"cwd":"/srv/repo"}`, true},
		{"mixed list", `{"argv":["fetch",1,"--force"]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": "tools/call",
				"params": map[string]any{"name": "git", "arguments": json.RawMessage(tc.arguments)},
			})
			if err != nil {
				t.Fatal(err)
			}
			values, _ := ArgValues(json.RawMessage(tc.arguments))
			for entry, v := range map[string]Verdict{
				"CheckRequest":      pc.CheckRequest(line),
				"CheckToolCallJSON": pc.CheckToolCallJSON("git", values, values, json.RawMessage(tc.arguments)),
			} {
				if blocked := v.Matched && v.Action == config.ActionBlock; blocked != tc.block {
					t.Errorf("%s: got %+v, want block=%v", entry, v, tc.block)
				}
			}
		})
	}
}

// TestGitSubcommandProofShellPrefix checks the shell command string reading:
// wrappers, assignments and separators keep a plain Git command's exception,
// and a Git command the plain reading cannot see, or reads differently from
// the normalized views, loses it.
func TestGitSubcommandProofShellPrefix(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{"cd /srv/repo && git fetch --force", false},
		{"sudo git fetch --force", false},
		{"GIT_TRACE=1 git fetch --force", false},
		{"/usr/bin/git fetch --force", false},
		{"git fetch --force; git status", false},
		{"git status && git add --force notes", false},
		{"git fetch --force && git r --ha", true},
		{"g''it fetch --force", true},
		{`g''it fe\x74ch --force`, true},
		{"git -C /srv/repo f''etch --force", true},
		{"x=$(git rogue --force)", true},
		{"x=`git rogue --force`", true},
		{"bash -c \"git f''etch --force\"", true},
		{"git -c 'x=1; y' fetch --force", true},
		// A plain Git command after an executable the views read as git, but
		// spelled otherwise, must not stand in for it: in a comment, after a
		// separator, or as a later operand.
		{`g''it fe\x74ch --hard # git fetch`, true},
		{`"git" fe\x74ch --force # git fetch`, true},
		{`g\it fe\x74ch --force # git fetch`, true},
		{`g''it fe\x74ch --hard git fetch`, true},
		{`'git' fe\x74ch --hard; git fetch`, true},
		{"cd \"/srv/repo\" && git fetch --force", false},
		{"echo 'note' # git fetch\ngit fetch --force", false},
		{"git -C", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			v := pc.CheckToolCall("bash", []string{tc.command})
			if blocked := v.Matched && v.Action == config.ActionBlock; blocked != tc.block {
				t.Errorf("got %+v, want block=%v", v, tc.block)
			}
		})
	}
}

func TestProveGitBuiltins(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		carriers []argCarrier
		gitTool  bool
		proved   []string
		unproved bool
	}{
		{"bash string", []string{"git fetch --force"}, nil, false, []string{"fetch"}, false},
		{"two commands", []string{"git fetch; git add x"}, nil, false, []string{"fetch", "add"}, false},
		{"covered utility", []string{"rm -r git fetch"}, nil, false, nil, false},
		{"no git", []string{"ls --force"}, nil, false, nil, false},
		{"git tool string", []string{"-C /srv fetch --force"}, nil, true, []string{"fetch"}, false},
		{"git tool argv", []string{"-C", "a b", "fetch"}, []argCarrier{{values: []string{"-C", "a b", "fetch"}, array: true}}, true, []string{"fetch"}, false},
		{"git tool separator", []string{"status; fetch"}, nil, true, nil, true},
		{"incomplete", []string{"git -C"}, nil, false, nil, true},
		{"ambiguous", []string{"git", "fetch x", "--force"}, nil, false, nil, true},
		{"two carriers", []string{"fetch", "--force"}, []argCarrier{{values: []string{"fetch"}}, {values: []string{"--force"}}}, true, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := proveGitBuiltins(tc.args, tc.carriers, tc.gitTool)
			if !slices.Equal(got.proved, tc.proved) || got.unproved != tc.unproved {
				t.Errorf("got %+v, want proved=%q unproved=%v", got, tc.proved, tc.unproved)
			}
		})
	}
}

func TestJSONArgCarriers(t *testing.T) {
	raw := json.RawMessage(`{"b":["x","y"],"a":"s","c":[1,"z"],"d":{"e":["w"]}}`)
	values, _ := ArgValues(raw)
	got := jsonArgCarriers(raw, values)
	want := []argCarrier{{values: []string{"s"}}, {values: []string{"x", "y"}, array: true}, {values: []string{"z"}}, {values: []string{"w"}, array: true}}
	if !slices.EqualFunc(got, want, func(a, b argCarrier) bool { return a.array == b.array && slices.Equal(a.values, b.values) }) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if jsonArgCarriers(raw, []string{"other"}) != nil {
		t.Fatal("a shape that does not reproduce the values must not be used")
	}
	if jsonArgCarriers(nil, nil) != nil || jsonArgCarriers(json.RawMessage(`{`), nil) != nil {
		t.Fatal("missing or malformed JSON has no shape")
	}
}
