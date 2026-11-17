// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// Bash is the independent producer: retain assignments in conditions,
// groups and commands whose redirections have trailing comments.
func TestShellConstructionKeptAssignmentsInCommands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX bash")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	cases := []struct{ name, before, after string }{
		{"quoted redirect target", "A=r >" + strconv.Quote(t.TempDir()+"/output file") + ";", ""},
		{"output process target", "A=r > >(true);", ""},
		{"input process target", "A=r < <(printf x);", ""},
		{"expansion comment", "A=r $u # comment\n", ""},
		{"redirect comment", "A=r >/dev/null # comment\n", ""},
		{"redirect comment with separator", "A=r >/dev/null # comment; ignored\n", ""},
		{"descriptor comment", "A=r >/dev/null 2>&1 # comment\n", ""},
		{"if condition", "if A=r >/dev/null; then :; fi;", ""},
		{"while condition", "while A=r >/dev/null; do break; done;", ""},
		{"until condition", "until A=r >/dev/null; do :; done;", ""},
		{"nested condition", "if true; then if A=r >/dev/null; then :; fi; fi;", ""},
		{"builtin condition", "if export A=r extra; then :; fi;", ""},
		{"named function group", "function f { A=r >/dev/null;", "; }; f"},
		{"named coprocess group", "coproc CHANNEL { A=r >/dev/null;", `; read -r reply; }; IFS= read -r -N 2 -u "${CHANNEL[0]}" result; printf %s "$result"; printf '\n' >&"${CHANNEL[1]}"; wait`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := tc.before + `B=m; printf %s "$A$B"` + tc.after
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-s")
			cmd.Stdin = strings.NewReader(script)
			cmd.Env = []string{"PATH=/usr/bin:/bin"}
			actual, err := cmd.Output()
			if err != nil || string(actual) != "rm" {
				t.Fatalf("bash printed %q, err=%v", actual, err)
			}
			out, partial, fits := resolveShellConstruction(script)
			if !fits || partial || !strings.Contains(out, "rm") {
				t.Fatalf("reading missed bash output: fits=%v partial=%v out=%q", fits, partial, out)
			}
			attack := tc.before + "B=m; " + d + "A" + d + "B -rf /tmp/target" + tc.after
			assertFileDelete(t, defaultBlockPolicy(""), attack)
		})
	}
	// These words occur after the command's assignment prefix. They are
	// executable names here, rather than condition keywords.
	for _, word := range []string{"if", "while", "until"} {
		in := "A=r " + word + " >/dev/null" + "; B=m; " + d + "A" + d + "B -rf /tmp/target"
		out, partial, fits := resolveShellConstruction(in)
		if !fits || partial || strings.Contains(out, "rm -rf") {
			t.Fatalf("read command word %q as a keyword: fits=%v partial=%v out=%q", word, fits, partial, out)
		}
	}
}

// Duplicate IFS assignments must not multiply the scan of every distinct
// value. This input previously spent seconds scanning an unchanged comma
// separator for values without commas, without consuming the work budget.
func TestShellConstructionRepeatedIFSBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(strings.Repeat("IFS=,;", 60000))
	for i := range 40000 {
		_, _ = fmt.Fprintf(&b, "A=v%d;", i)
	}
	b.WriteString("echo " + d + "A")
	in := b.String()
	start := time.Now()
	out, partial, fits := resolveShellConstruction(in)
	elapsed := time.Since(start)
	t.Logf("%d bytes resolved in %s", len(in), elapsed)
	if !fits || partial || !strings.Contains(out, "echo v39999") {
		t.Fatalf("fits=%v partial=%v output bytes=%d", fits, partial, len(out))
	}
	if elapsed > 5*time.Second {
		t.Fatalf("duplicate IFS values multiplied the scan: %s", elapsed)
	}
	// Distinct separators still contribute their readings.
	assertFileDelete(t, defaultBlockPolicy(""), "IFS=,; IFS=:; A=r:m; "+d+"A -rf /tmp/target")
}
