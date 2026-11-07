// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import "testing"

func TestShellCommandScriptState(t *testing.T) {
	pc := defaultConfigWithIncomplete(t, "block")
	// These are submitted programs, never executed. An earlier or later
	// non-read-only statement revokes data exemptions for the entire script.
	tests := []struct{ name, command string }{
		{"exec process substitution", "exec > >(bash)\necho 'git reset --hard'"},
		{"exec file replay", "exec 1>program.sh\necho 'git reset --hard'\nexec 1>/dev/tty\nbash program.sh"},
		{"exec descriptor alias", "exec 3> >(sh)\nexec 1>&3\necho 'git reset --hard'"},
		{"both streams pipeline", `echo 'git reset --hard' |& bash`},
		{"file replay", `echo 'git reset --hard' > program.sh; sh program.sh`},
		{"coprocess descriptor", "coproc bash\necho 'git reset --hard' >&\"${COPROC[1]}\""},
		{"fifo replay", "mkfifo channel\nbash < channel &\necho 'git reset --hard' > channel"},
		{"recorded shell", `script -qc "echo 'git reset --hard'" /dev/null`},
		{"history file replay", "echo 'git reset --hard'\nhistory -w history.txt; bash history.txt"},
		{"history substitution replay", "set -o history\necho 'git reset --hard'\nfc -s echo=bash"},
		{"printf variable replay", `printf -v action '%s' 'git reset --hard'; eval "$action"`},
		{"printf variable data", `printf -v action '%s' 'git reset --hard'`},
		{"printf count assignment", `printf '%n' count; echo 'git reset --hard'`},
		{"printf width count assignment", `printf '%10ln' count; echo 'git reset --hard'`},
		{"variable test", `test -v 'items[index=1]'; echo 'git reset --hard'`},
		{"variable bracket test", `[ -v 'items[index=1]' ]; echo 'git reset --hard'`},
		{"nameref test", `test -R name; echo 'git reset --hard'`},
		{"exec stderr", "exec 2>&1\necho 'git reset --hard'"},
		{"exec close descriptor", "exec 1>&-\necho 'git reset --hard'"},
		{"exec input", "exec < program.sh\necho 'git reset --hard'"},
		{"history append", "history -a history.txt\necho 'git reset --hard'"},
		{"history read", "history -r history.txt\necho 'git reset --hard'"},
		{"history restore", "history -n history.txt\necho 'git reset --hard'"},
		{"history builtin", "history\necho 'git reset --hard'"},
		{"fc editor", "fc -e bash\necho 'git reset --hard'"},
		{"fc last", "echo 'git reset --hard'\nfc -s"},
		{"exit trap", `trap 'bash program.sh' EXIT; echo 'git reset --hard'`},
		{"debug trap", `trap "$handler" DEBUG; echo 'git reset --hard'`},
		{"coprocess group", `coproc channel { cat; }; echo 'git reset --hard'`},
		{"recorded shell option", `script --command "echo 'git reset --hard'" /dev/null`},
		{"unknown setup", "prepare\necho 'git reset --hard'"},
		{"later unknown statement", "echo 'git reset --hard'\nprepare"},
		{"ordinary assignment", "label=sample\necho 'git reset --hard'"},
		{"local declaration", `local label=sample; grep 'git reset --hard' notes.txt`},
		{"background", `true & echo 'git reset --hard'`},
		{"background after", `echo 'git reset --hard' &`},
		{"empty function", `prepare() { }; echo 'git reset --hard'`},
		{"empty group", `{ }; echo 'git reset --hard'`},
		{"hidden substitution", `echo "$(prepare)"; echo 'git reset --hard'`},
		{"dynamic argument", `echo "$label"; echo 'git reset --hard'`},
		{"parameter assignment", `echo "${label:=sample}"; echo 'git reset --hard'`},
		{"hostname subprocess", `rg --hostname-bin prepare sample notes.txt; echo 'git reset --hard'`},
		{"sort subprocess", `sort --compress-program prepare; echo 'git reset --hard'`},
		{"sort output", `sort -o program.sh; echo 'git reset --hard'`},
		{"uniq output", `uniq notes.txt program.sh; echo 'git reset --hard'`},
		{"date set", `date -s tomorrow; echo 'git reset --hard'`},
		{"git without option classification", `git status --short; echo 'git reset --hard'`},
		{"unquoted command data", "echo git reset --hard"},
		{"filter after directory change", "cd workspace; grep 'git reset --hard' notes.txt"},
		{"sed edits file", "sed -i '/git reset --hard/p' notes.txt"},
		{"sed executes command", "sed -n '/git reset --hard/e' notes.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if v := pc.CheckShellCommand(tt.command, nil); !v.Matched || v.Action != "block" {
				t.Fatalf("script retained a data exemption: %+v", v)
			}
		})
	}
}

func TestShellCommandReadOnlyScript(t *testing.T) {
	pc := defaultConfigWithIncomplete(t, "block")
	commands := []string{
		"echo sample", "printf '%s' sample", "grep sample notes.txt", "egrep sample notes.txt",
		"fgrep sample notes.txt", "rg sample notes.txt", "cat notes.txt", "ls", "head notes.txt",
		"tail notes.txt", "wc notes.txt", "true", "false", "test -f notes.txt", "[ -f notes.txt ]",
		"sort", "uniq", "cut -c 1 notes.txt", "tr a b", "basename notes.txt", "dirname notes.txt",
		"pwd", "date", "sed -n '/sample/p' notes.txt", "git clean -fdn", "cd workspace",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			if v := pc.CheckShellCommand(command+"\necho 'git reset --hard'", nil); v.Matched {
				t.Fatalf("read-only script lost its data exemption: %+v", v)
			}
		})
	}
	for _, command := range []string{
		`echo 'never run git reset --hard'`,
		`grep -rn 'git reset --hard' docs || true`,
		`egrep 'git reset --hard' notes.txt`,
		`fgrep 'git reset --hard' notes.txt`,
		`printf -- '%s\n' 'git reset --hard'`,
		`printf '%%n %*.*s' 10 2 'git reset --hard'`,
		`grep -F 'git clean -fdx' notes.txt || true; echo 'inspect the results'`,
	} {
		if v := pc.CheckShellCommand(command, nil); v.Matched {
			t.Errorf("literal data matched: %+v", v)
		}
	}
}
