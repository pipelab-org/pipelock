// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestDefaultRules_XargsInputBoundary(t *testing.T) {
	inc := incompletePairCheckRule
	runVerdictRows(t, []verdictRow{
		{"filename words", "find . -name 'x -R y' | xargs chmod 777", inc, rulePermissions},
		{"filename not in command", "find . -type f | xargs chmod 777", inc, rulePermissions},
		{"ordinary mode", "find /srv -type f | xargs chmod 644", inc, rulePermissions},
		{"null names", "find . -type f -print0 | xargs -0 chmod 777", "", ""},
		{"long null option", "/usr/bin/find ./mypath -name '*.txt' -print0 | /usr/bin/xargs --null chmod 644", "", ""},
		{"missing null consumer", "find . -print0 | xargs chmod 777", inc, rulePermissions},
		{"unproved producer framing", "find . -print | xargs -0 chmod 777", inc, rulePermissions},
		{"action word is test argument", "find . -name -print0 | xargs -0 chmod 777", inc, rulePermissions},
		{"file input", "find . -print0 | xargs -0 -a list chmod 777", inc, rulePermissions},
		{"redirect input", "find . -print0 | xargs -0 chmod 777 < list", inc, rulePermissions},
		{"delimiter override", "find . -print0 | xargs -0 -d '\\n' chmod 777", inc, rulePermissions},
		{"replacement", "find . -print0 | xargs -I{} chmod 777 {}", inc, rulePermissions},
		{"unknown option", "find . -print0 | xargs --unknown chmod 777", inc, rulePermissions},
		{"other output", "find . -print0 -ls | xargs -0 chmod 777", inc, rulePermissions},
		{"unknown producer", "grep -rl x . | xargs -0 chmod 777", inc, rulePermissions},
		{"grouped consumer", "find . -print0 | { xargs chmod 777; }", inc, rulePermissions},
		{"subshell consumer", "find . -print0 | (xargs chmod 777)", inc, rulePermissions},
		{"no argument consumer", "find . -type f | chmod 777", "", ""},
		{"literal producer", "echo 755 ./build | xargs chmod", "", ""},
	})
}

func TestKnownXargsInput(t *testing.T) {
	for _, command := range []string{
		"", "echo x", "find . -print0", "| xargs chmod x", "find . -print0 | xargs",
		"find . -print0 | cat | xargs -0 chmod", "find . -print0 | cat -0 chmod",
		"find . -print0 | xargs -0", "find . -print0 | xargs -0 -a list chmod",
		"find relative -print0 | xargs -0 chmod", "find . -print0 -print0 | xargs -0 chmod",
		"find . -perm | xargs -0 chmod", "find . -type f | xargs -0 chmod",
		"find . -name '-print0' | xargs -0 chmod", "find . -print | xargs -0 chmod",
		"find . -print0 | xargs -0 ''", "find . -print0 | xargs -0 chmod < list",
		"find $HOME -print0 | xargs -0 chmod", "find . -name *.txt -print0 | xargs -0 chmod",
		"find . -name 'open -print0 | xargs -0 chmod", "find .\n-print0 | xargs -0 chmod",
	} {
		t.Run(command, func(t *testing.T) {
			if got := knownXargsInput([]string{command}); got != "" {
				t.Fatalf("unproved input exempted for %q", got)
			}
		})
	}
	for _, command := range []string{
		"find . -print0 | xargs -0 chmod 644",
		"find -L /srv -name '*.txt' -print0|xargs --null chmod 644",
		"find -print0 | xargs -0 chmod 644",
		"echo 755 /srv | xargs chmod",
	} {
		if got := knownXargsInput([]string{command}); got != "chmod" {
			t.Errorf("%q: got %q, want chmod", command, got)
		}
	}
	if got := knownXargsInput([]string{"find", ".", "-print0", "|", "xargs", "-0", "chmod"}); got != "" {
		t.Fatalf("argument array exempted for %q", got)
	}
}

// TestDefaultRules_FindPrintsOnlyPaths checks that the options and tests of
// a find whose output is only path names are not taken as words it hands
// on, and that every find that may print or run anything else, or may not
// be find, is still checked.
func TestDefaultRules_FindPrintsOnlyPaths(t *testing.T) {
	inc := incompletePairCheckRule
	runVerdictRows(t, []verdictRow{
		{"perm test", "find /srv -type f -perm 0777 -print0 | xargs -0 chmod 644", "", ""},
		{"perm test, print0", "find . -perm -777 -print0 | xargs -0 chmod 755", "", ""},
		{"leading option", "find -L /srv -perm 0777 -print0 | xargs -0 chmod 644", "", ""},
		{"path test", "find /srv -path /srv/x -perm 0777 -print0 | xargs -0 chmod 644", "", ""},
		{"full path", "/usr/bin/find /srv -perm 777 -type f -print0 | xargs -0 chmod 644", "", ""},
		{"own flag, paths handed", "find /srv -perm 777 -print0 | xargs -0 chmod -R", "", ""},

		// Starting points are printed.
		{"starting point", "find 777 -type f | xargs chmod -R", inc, rulePermissions},
		{"starting point after an option", "find -L 777 -perm 1 | xargs chmod -R", inc, rulePermissions},
		// Output other than paths, or errors joined in.
		{"ls", "find /srv -perm 777 -ls | xargs chmod -R", inc, rulePermissions},
		{"printf", "find /srv -printf -R -perm 777 | xargs chmod", inc, rulePermissions},
		{"fprint to stdout", "find /srv -perm 777 -fprint /dev/stdout | xargs chmod -R", inc, rulePermissions},
		{"errors joined", "find /srv -perm 777 2>&1 | xargs chmod -R", inc, rulePermissions},
		{"errors piped", "find /srv -perm 777 |& xargs chmod -R", inc, rulePermissions},
		{"exec", "find /srv -perm 777 -exec echo -R ; | xargs chmod", inc, rulePermissions},
		{"starting point option", "find -f 777 -perm -R | xargs chmod", inc, rulePermissions},
		{"end of options", "find /srv -- -perm 777 | xargs chmod -R", inc, rulePermissions},
		{"starting point after a BSD option", "find -x 777 -type f | xargs chmod -R", inc, rulePermissions},
		{"starting point after bundled options", "find -sL 777 -type f | xargs chmod -R", inc, rulePermissions},
		{"debug value", "find -D 777 /srv -perm 1 | xargs chmod -R", inc, rulePermissions},
		// May not be find.
		{"PATH", "PATH=/tmp find /srv -perm 777 | xargs chmod -R", inc, rulePermissions},
		{"relative path", "./find /srv -perm 777 | xargs chmod -R", inc, rulePermissions},
		{"after sudo", "sudo find /srv -perm 777 | xargs chmod -R", inc, rulePermissions},
		{"hash", "hash -p /bin/echo find; find -R 777 | xargs chmod", inc, rulePermissions},
		{"PATH exported", "export PATH=/tmp; find /srv -perm 777 | xargs chmod -R", inc, rulePermissions},
		{"PATH set first", "PATH=/tmp; find /srv -perm 777 | xargs chmod -R", inc, rulePermissions},
		{"PATH appended", "PATH+=:/tmp; find /srv -perm 777 | xargs chmod -R", inc, rulePermissions},
		{"zsh path", "path=(/tmp); find /srv -perm 777 | xargs chmod -R", inc, rulePermissions},
		{"function", "find() { echo -R 777 /srv; }; find /srv -perm 1 | xargs chmod", inc, rulePermissions},
		{"function keyword", "function find { echo -R 777 /srv; }; find /srv -perm 1 | xargs chmod", inc, rulePermissions},
		{"sourced", "source ./x; find /srv -perm 777 | xargs chmod -R", inc, rulePermissions},
		{"dot sourced", ". ./x; find /srv -perm 777 | xargs chmod -R", inc, rulePermissions},
		{"eval", "eval $x; find /srv -perm 777 | xargs chmod -R", inc, rulePermissions},
		// Other producers keep every word.
		{"grep", "grep -rl 777 docs | xargs chmod -R", inc, rulePermissions},
		{"echo", "echo -R 777 /srv | xargs chmod", inc, rulePermissions},
	})
}

// TestFindPathsOnly checks the words kept for each find.
func TestFindPathsOnly(t *testing.T) {
	tests := []struct {
		cmd, want string
	}{
		{"find /srv -type f -perm 0777 | xargs chmod", "find /srv | xargs chmod"},
		{"find /srv -perm 0777| xargs chmod", "find /srv | xargs chmod"},
		{"find -L -O2 -D tree /a /b -perm 1 ; ls -R", "find tree /a /b ; ls -R"},
		{"find /a ( -perm 1 ) > out", "find /a >"},
		{"ls -R; find /a -perm 1", "ls -R; find /a"},
		{"echo find -perm 777", "echo find -perm 777"},
		{"find /a -perm 1 -ls | xargs chmod", "find /a -perm 1 -ls | xargs chmod"},
		{"find /a -perm 1 2>&1 | xargs chmod", "find /a -perm 1 2>&1 | xargs chmod"},
		{"find /a -perm 1 -EXEC x | xargs chmod", "find /a -perm 1 -EXEC x | xargs chmod"},
		{"find -x -E /a -perm 1 | xargs chmod", "find /a | xargs chmod"},
		{"find -D tree /a -perm 1 | xargs chmod", "find tree /a | xargs chmod"},
		{"find /a -perm 1 -print; xargs chmod", "find /a ; xargs chmod"},
		{"{ find /a -perm 1; } | xargs chmod", "{ find /a -perm 1; } | xargs chmod"},
		{"alias find=echo; find /a -perm 1 | xargs chmod", "alias find=echo; find /a -perm 1 | xargs chmod"},
		{"hash -p /bin/echo find; find /a -perm 1", "hash -p /bin/echo find; find /a -perm 1"},
		{"PATH=/tmp find /a -perm 1 | xargs chmod", "PATH=/tmp find /a -perm 1 | xargs chmod"},
		{"./find /a -perm 1 | xargs chmod", "./find /a -perm 1 | xargs chmod"},
		{"export PATH=/x; find /a -perm 1", "export PATH=/x; find /a -perm 1"},
		{"path=(/x); find /a -perm 1", "path=(/x); find /a -perm 1"},
		{"find() { :; }; find /a -perm 1", "find() { :; }; find /a -perm 1"},
		{". x; find /a -perm 1", ". x; find /a -perm 1"},
		{"find /a -path /a/b -perm 1", "find /a"},
		{"sudo find /a -perm 1 | xargs chmod", "sudo find /a -perm 1 | xargs chmod"},
		{"find /a -perm 1 -ls;x | xargs chmod", "find /a -perm 1 -ls;x | xargs chmod"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			got := findPathsOnly([][]string{strings.Fields(tt.cmd)})
			if want := [][]string{strings.Fields(tt.want)}; !slices.EqualFunc(got, want, slices.Equal[[]string]) {
				t.Fatalf("findPathsOnly(%q) = %q, want %q", tt.cmd, got, want)
			}
		})
	}
}
