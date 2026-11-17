// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// d keeps shell dollar signs out of Go string literals that linters read as
// template syntax.
const d = "$"

// Values that name other assigned variables re-expanded on every iteration,
// so a few bytes of input grew into gigabytes. Resolution must stay within
// maxShellConstructionLen and say when it stopped.
func TestResolveShellConstructionBoundsGrowth(t *testing.T) {
	cases := []struct {
		name string
		in   string
		fits bool
	}{
		{"parameter chain", "echo '" + d + "a=" + d + "b=" + d + "c=;'", true},
		{"long parameter chain", "echo '" + d + "a=" + d + "b=" + d + "c=" + d + "d=" + d + "e=" + d + "f=;'", true},
		{"awk fields", "awk '{printf \"pid=%s \", " + d + "1; " + d + "1=" + d + "2=" + d + "3=\"\"; print substr(" + d + "0,1,150)}'", true},
		// b is unset when a is assigned, as in the shell, so this is finite.
		{"mutual assignment", "a=" + d + "b" + d + "b;b=" + d + "a" + d + "a;" + d + "a", true},
		{"doubling", doublingBomb(), false},
		// A self-reference reads the earlier (unset) value, as the shell does, so
		// it cannot grow.
		{"self reference", "x=" + d + "x" + d + "x" + d + "x;" + d + "x " + d + "x", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _, fits := resolveShellConstruction(tc.in)
			if limit := maxShellConstructionLen(len(tc.in)); len(out) > limit {
				t.Fatalf("expanded to %d bytes, limit %d", len(out), limit)
			}
			if fits != tc.fits {
				t.Fatalf("fits = %v, want %v", fits, tc.fits)
			}
		})
	}
}

// The bound must not stop the expansions the resolver exists for.
func TestResolveShellConstructionStillExpands(t *testing.T) {
	cases := map[string]string{
		"x=rm;" + d + "x -rf /":                           "rm -rf /",
		"x=rm;" + d + "{x} -rf /":                         "rm -rf /",
		"IFS=,;CMD=r,m;" + d + "CMD -rf /":                "rm -rf /",
		d + "(printf rm) -rf /":                           "rm -rf /",
		"a=r;b=" + d + "a;" + d + "{b}m -rf":              "rm -rf",
		"v=IFS;rm" + d + "{!v:0:1}-rf":                    "rm${IFS:0:1}-rf",
		"x=/bin/rm;: " + strings.Repeat(d+"x ", 70) + ";": "/bin/rm /bin/rm",
	}
	for in, want := range cases {
		out, _, fits := resolveShellConstruction(in)
		if !fits || !strings.Contains(out, want) {
			t.Errorf("resolveShellConstruction(%q) = %q fits=%v, want it to contain %q", in, out, fits, want)
		}
	}
}

// `$1=` and `$a=` reference a parameter and assign nothing.
func TestResolveShellConstructionIgnoresParameterReferences(t *testing.T) {
	for _, in := range []string{
		"echo '" + d + "a=" + d + "b=" + d + "c=;'",
		"awk '{" + d + "1=" + d + "2=" + d + "3=\"\"; print}'",
	} {
		if out, _, fits := resolveShellConstruction(in); !fits || out != in {
			t.Errorf("resolveShellConstruction(%q) = %q fits=%v, want it unchanged", in, out, fits)
		}
	}
}

// doublingBomb doubles a value 40 times; the shell would build 2^40 bytes.
func doublingBomb() string {
	return "a=x;" + strings.Repeat("a="+d+"a"+d+"a;", 40) + d + "a"
}

// testRand is a fixed-seed generator for the generated-input tests, so a
// failure names the same input on every run.
type testRand uint32

func (r *testRand) IntN(n int) int {
	x := uint32(*r)
	x ^= x << 13
	x ^= x >> 17
	x ^= x << 5
	*r = testRand(x)
	return int(x>>1) % max(n, 1)
}

func defaultBlockPolicy(incomplete string) *Config {
	return New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, OnIncompleteCheck: incomplete, Rules: DefaultToolPolicyRules()})
}

// A command hidden in a variable expanded many times still resolves and
// matches its rule; padding is not a way to reach a warning.
func TestShellConstructionPaddingStillBlocks(t *testing.T) {
	hidden := "x=/" + strings.Repeat("./", 600) + "bin/rm;: " + strings.Repeat(d+"x ", 70) + ";" + d + "x -rf /tmp/target"
	v := defaultBlockPolicy("").CheckToolCall("bash", []string{hidden})
	if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, ruleFileDelete) {
		t.Fatalf("verdict %v %q %v", v.Matched, v.Action, v.Rules)
	}
}

// rmStartsCommand matches rm as a command word. "echorm -rf" contains the
// text "rm -rf" too, so a substring check cannot tell the readings apart.
var rmStartsCommand = regexp.MustCompile(`(^|[;&|]\s*)rm -rf /tmp/target`)

// A use before the name's first assignment runs with the name unset; a later
// decoy assignment must not be its only reading.
func TestShellConstructionUseBeforeAssignmentReadsUnset(t *testing.T) {
	cmd := "A=r; B=m; " + d + "Z" + d + "A" + d + "B -rf /tmp/target; Z=echo"
	out, partial, fits := resolveShellConstruction(cmd)
	if !fits || partial || !rmStartsCommand.MatchString(out) {
		t.Fatalf("out=%q partial=%v fits=%v, want the unset reading", out, partial, fits)
	}
	assertFileDelete(t, defaultBlockPolicy(""), cmd)

	// An assignment that may not run, or is undone, leaves the name unset.
	use := "A=r; B=m; " + d + "Z" + d + "A" + d + "B -rf /tmp/target"
	for _, cmd := range []string{
		"test -f /nope && Z=echo; " + use,
		"test -f /nope || Z=echo; " + use,
		"if test -f /nope; then Z=echo; fi; " + use,
		"(Z=echo); " + use,
		"{ Z=echo; }; " + use,
		"f() { Z=echo; }; " + use,
		"Z=echo; unset Z; " + use,
	} {
		out, partial, fits := resolveShellConstruction(cmd)
		if !fits || partial || !rmStartsCommand.MatchString(out) {
			t.Fatalf("%q: out=%q partial=%v fits=%v, want the unset reading", cmd, out, partial, fits)
		}
		assertFileDelete(t, defaultBlockPolicy(""), cmd)
	}

	// Review round: the empty reading pairs with every value of the other
	// names; a reserved word that is data does not close a block; a quoted
	// unset still unsets; an assignment in a pipeline or background job does
	// not reach the shell.
	for _, cmd := range []string{
		"A=ls; A=r; B=m; " + d + "Z" + d + "A" + d + "B -rf /tmp/target; Z=echo",
		"if test -f /nope; then echo fi; Z=echo; fi; " + use,
		"if test -f /nope; then echo 'fi'; Z=echo; fi; " + use,
		"Z=echo; unset \"Z\"; " + use,
		"Z=echo; unset 'Z'; " + use,
		"Z=echo | cat; " + use,
		"Z=echo & " + use,
		// A "!" before a block, a reserved word that is data, a comment
		// after ";".
		"! if test -f /nope; then Z=echo; fi; " + use,
		"if test -f /nope; then echo !fi; Z=echo; fi; " + use,
		// The hosted review's cases on 7a82b1d.
		"if false; then echo done; Z=echo; fi; " + use,
		"Z=echo; unset Z>/dev/null; " + use,
		"A=echo; A=r; B=m; false && Z=x; " + d + "Z" + d + "A" + d + "B -rf /tmp/target",
		"echo if; if test -f /nope; then Z=echo; fi; " + use,
		"true;#x\nif test -f /nope; then Z=echo; fi; " + use,
	} {
		out, _, fits := resolveShellConstruction(cmd)
		if !fits || !rmStartsCommand.MatchString(out) {
			t.Fatalf("%q: out=%q fits=%v, want the unset reading", cmd, out, fits)
		}
		assertFileDelete(t, defaultBlockPolicy(""), cmd)
	}

	// An assignment that always runs first is not read as unset.
	out, _, _ = resolveShellConstruction("Z=echo; " + use)
	if strings.Contains(out, "; rm -rf") {
		t.Fatalf("unconditional assignment read as unset: %q", out)
	}
}

// An assignment before a special builtin is kept by sh and dropped by bash,
// so the use must read both: with the value and unset.
func TestShellConstructionSpecialBuiltinReadsBothShells(t *testing.T) {
	for _, cmd := range []string{
		"C=x :; " + d + "{C}rm -rf /tmp/t",
		"C=x eval true; " + d + "{C}rm -rf /tmp/t",
		"C=x D=y :; " + d + "{C}rm -rf /tmp/t",
		"C=x D=y eval true; " + d + "{C}rm -rf /tmp/t",
		"C=x >/dev/null :; " + d + "{C}rm -rf /tmp/t",
	} {
		out, partial, fits := resolveShellConstruction(cmd)
		if !fits || partial || !strings.Contains(out, "; rm -rf /tmp/t") || !strings.Contains(out, "xrm -rf /tmp/t") {
			t.Fatalf("%q: out=%q partial=%v fits=%v, want both the unset and the kept reading", cmd, out, partial, fits)
		}
		v := defaultBlockPolicy("").CheckToolCall("bash", []string{cmd})
		if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, ruleFileDelete) {
			t.Fatalf("%q: verdict %v %q %v", cmd, v.Matched, v.Action, v.Rules)
		}
	}
	// A self-referencing prefix value: the use stays braced, which the policy
	// reads as empty, so the unset reading still reaches the rule.
	assertFileDelete(t, defaultBlockPolicy(""), "C="+d+"{C}x :; "+d+"{C}rm -rf /tmp/t")
}

// Text whose expansion passes the bound blocks under every
// on_incomplete_check setting, including the default warn, and through every
// entry that reads shell arguments.
func TestShellConstructionOverflowBlocks(t *testing.T) {
	overflow := doublingBomb() + " -rf /tmp/target"
	for _, incomplete := range []string{"", config.ActionWarn, config.ActionBlock} {
		pc := defaultBlockPolicy(incomplete)
		for name, v := range map[string]Verdict{
			"args":  pc.CheckToolCall("bash", []string{overflow}),
			"keyed": pc.CheckToolCallWithArgs("bash", []string{overflow}, json.RawMessage(`{"command":"`+overflow+`"}`)),
		} {
			if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, uninspectableShellConstructionRule) {
				t.Errorf("on_incomplete_check %q %s: verdict %v %q %v", incomplete, name, v.Matched, v.Action, v.Rules)
			}
		}
	}
}

// The awk idiom from the report is ordinary text, not a policy match.
func TestShellConstructionAwkFieldsAllowed(t *testing.T) {
	cmd := "awk '{printf \"pid=%s \", " + d + "1; " + d + "1=" + d + "2=" + d + "3=\"\"; print substr(" + d + "0,1,150)}'"
	if v := defaultBlockPolicy("").CheckToolCall("bash", []string{cmd}); v.Matched {
		t.Fatalf("awk field reset matched: %q %v", v.Action, v.Rules)
	}
}

// $a must not rewrite $ab, and parameter references must not hide a later
// assignment. A chain that still changes after the last substitution pass
// is not a finished command.
func TestShellConstructionReviewRepro(t *testing.T) {
	pc := defaultBlockPolicy("")
	prefix := "a=echo;ab=/bin/rm;" + d + "ab -rf /tmp/target"
	out, _, fits := resolveShellConstruction(prefix)
	if !fits || !strings.Contains(out, "/bin/rm -rf") || strings.Contains(out, "echob") {
		t.Fatalf("prefix expansion %q fits=%v", out, fits)
	}
	assertFileDelete(t, pc, prefix)

	var fill strings.Builder
	for i := 1; i <= 10; i++ {
		fill.WriteString(d + strconv.Itoa(i) + "=a;")
	}
	fill.WriteString("x=/bin/rm;" + d + "x -rf /tmp/target")
	out, _, fits = resolveShellConstruction(fill.String())
	if !fits || !strings.Contains(out, "/bin/rm -rf") {
		t.Fatalf("filler expansion %q fits=%v", out, fits)
	}
	assertFileDelete(t, pc, fill.String())

	deep10 := assignmentChain(10)
	out, _, fits = resolveShellConstruction(deep10)
	if !fits || !strings.Contains(out, "/bin/rm -rf") {
		t.Fatalf("depth 10 expansion %q fits=%v", out, fits)
	}
	assertFileDelete(t, pc, deep10)

	deep11 := assignmentChain(11)
	v := pc.CheckToolCall("bash", []string{deep11})
	if !v.Matched || v.Action != config.ActionBlock {
		t.Fatalf("depth 11 allowed: %v %q %v", v.Matched, v.Action, v.Rules)
	}
	if !slices.Contains(v.Rules, ruleFileDelete) && !slices.Contains(v.Rules, uninspectableShellConstructionRule) {
		t.Fatalf("depth 11 rules %v", v.Rules)
	}

	var benign strings.Builder
	for i := 1; i <= 15; i++ {
		benign.WriteString("v" + strconv.Itoa(i) + "=" + strconv.Itoa(i) + ";")
	}
	benign.WriteString("echo")
	for i := 1; i <= 15; i++ {
		benign.WriteString(" " + d + "v" + strconv.Itoa(i))
	}
	out, _, fits = resolveShellConstruction(benign.String())
	if !fits || strings.Contains(out, "/bin/rm") {
		t.Fatalf("benign expansion %q fits=%v", out, fits)
	}
	if v := pc.CheckToolCall("bash", []string{benign.String()}); v.Matched {
		t.Fatalf("15 assignments matched: %q %v", v.Action, v.Rules)
	}
}

// nestedEchoRM wraps rm in depth command substitutions. Each pass unwraps one
// layer.
func nestedEchoRM(depth int) string {
	s := "rm"
	for range depth {
		s = "$(echo " + s + ")"
	}
	return s + " -rf /tmp/target"
}

// Nested substitutions resolve to the command they hide. Text that is still
// unwrapping when the passes run out is not a finished command, even though
// it stays small. A value that only names itself is finished.
func TestShellConstructionUnfinishedCommandSubBlocks(t *testing.T) {
	pc := defaultBlockPolicy("")
	for _, depth := range []int{10, 11, maxShellConstructionPasses - 1} {
		done := nestedEchoRM(depth)
		out, _, fits := resolveShellConstruction(done)
		if !fits || !strings.Contains(out, "rm -rf") {
			t.Fatalf("%d substitutions %q fits=%v", depth, out, fits)
		}
		assertFileDelete(t, pc, done)
	}

	pending := nestedEchoRM(maxShellConstructionPasses)
	out, _, fits := resolveShellConstruction(pending)
	if fits {
		t.Fatalf("substitutions past the pass cap %q reported finished", out)
	}
	v := pc.CheckToolCall("bash", []string{pending})
	if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, uninspectableShellConstructionRule) {
		t.Fatalf("past the pass cap verdict %v %q %v", v.Matched, v.Action, v.Rules)
	}

	stable := "a=" + d + "a;echo " + d + "a"
	out, _, fits = resolveShellConstruction(stable)
	if !fits || strings.Contains(out, "!") {
		t.Fatalf("self-reference %q fits=%v", out, fits)
	}
	if v := pc.CheckToolCall("bash", []string{stable}); v.Matched {
		t.Fatalf("self-reference matched: %q %v", v.Action, v.Rules)
	}
}

func assignmentChain(depth int) string {
	var b strings.Builder
	b.WriteString("v1=/bin/rm;")
	for i := 2; i <= depth; i++ {
		b.WriteString("v" + strconv.Itoa(i) + "=" + d + "v" + strconv.Itoa(i-1) + ";")
	}
	b.WriteString(d + "v" + strconv.Itoa(depth) + " -rf /tmp/target")
	return b.String()
}

func assertFileDelete(t *testing.T, pc *Config, cmd string) {
	t.Helper()
	v := pc.CheckToolCall("bash", []string{cmd})
	if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, ruleFileDelete) {
		t.Fatalf("verdict %v %q %v, want %s", v.Matched, v.Action, v.Rules, ruleFileDelete)
	}
}

// Positional text such as $1=a is not an assignment. Any amount of it must
// not make a following echo unreadable, and must not hide a later real
// assignment.
func TestShellConstructionPositionalFillers(t *testing.T) {
	pc := defaultBlockPolicy("")
	benign := positionalFillers(t, false)
	if v := pc.CheckToolCall("bash", []string{benign}); v.Matched {
		t.Fatalf("positional fillers blocked a plain echo: %q %v", v.Action, v.Rules)
	}
	hidden := positionalFillers(t, true)
	assertFileDelete(t, pc, hidden)
}

func positionalFillers(_ *testing.T, hide bool) string {
	var b strings.Builder
	b.WriteString("p=" + strings.Repeat("a", 20000) + ";")
	for range 500 {
		b.WriteString(d + "1=a;")
	}
	if hide {
		b.WriteString("x=/bin/rm;" + d + "x -rf /tmp/target")
	} else {
		b.WriteString("echo hello")
	}
	return b.String()
}

// manyNames builds n one-level assignments and uses each of them. With
// hide, the last name carries the command.
func manyNames(n int, hide bool) string {
	var b strings.Builder
	b.WriteString("p=" + strings.Repeat("a", 20000) + ";")
	for i := 1; i <= n; i++ {
		b.WriteString("v" + strconv.Itoa(i) + "=1;")
	}
	if hide {
		b.WriteString("x=/bin/rm;")
	}
	b.WriteString("echo")
	for i := 1; i <= n; i++ {
		b.WriteString(" " + d + "v" + strconv.Itoa(i))
	}
	if hide {
		b.WriteString(" " + d + "x -rf /tmp/target")
	}
	return b.String()
}

// A pass reads the command once however many names it uses, so a long
// script finishes, and a command built after many names is still found.
func TestShellConstructionManyNamesExpand(t *testing.T) {
	pc := defaultBlockPolicy("")
	benign := manyNames(2000, false)
	if _, _, fits := resolveShellConstruction(benign); !fits {
		t.Fatal("one-level script with many names was left unfinished")
	}
	if v := pc.CheckToolCall("bash", []string{benign}); v.Matched {
		t.Fatalf("one-level script matched: %q %v", v.Action, v.Rules)
	}
	assertFileDelete(t, pc, manyNames(2000, true))
}

// A use reads the assignment before it, not a later one.
func TestShellConstructionUseReadsEarlierAssignment(t *testing.T) {
	pc := defaultBlockPolicy("")
	assertFileDelete(t, pc, "X=/bin/rm; "+d+"X -rf /tmp/target; X=ls;")
	assertFileDelete(t, pc, "X=ls; X=/bin/rm; "+d+"X -rf /tmp/target")
}

// Many names that each repeat a large value must stop at the size bound
// rather than build every copy. Before the bound was enforced on output,
// this input of under 300 KB allocated gigabytes.
func TestShellConstructionFanOutBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("b=" + strings.Repeat("z", 160<<10) + ";")
	for i := range 3000 {
		b.WriteString("a" + strconv.Itoa(i) + "=" + strings.Repeat(d+"b", 15) + ";")
	}
	for i := range 3000 {
		b.WriteString(d + "a" + strconv.Itoa(i) + " ")
	}
	in := b.String()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	out, _, fits := resolveShellConstruction(in)
	runtime.ReadMemStats(&after)
	if fits {
		t.Fatal("fan-out reported finished")
	}
	limit := maxShellConstructionLen(len(in))
	if len(out) > limit {
		t.Fatalf("output %d bytes, limit %d", len(out), limit)
	}
	// One pass may allocate a few multiples of the limit as the builder
	// grows; a per-name copy of the value would be thousands of them.
	const maxAllocPerLimit = 64
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc/maxAllocPerLimit > uint64(max(limit, 0)) {
		t.Fatalf("allocated %d bytes for limit %d", alloc, limit)
	}
	v := defaultBlockPolicy("").CheckToolCall("bash", []string{in})
	if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, uninspectableShellConstructionRule) {
		t.Fatalf("fan-out verdict %v %q %v", v.Matched, v.Action, v.Rules)
	}
}

// A JSON key is not one of the argument strings, but credential matching
// reads it. An expansion that stops inside that key is still unfinished.
func TestShellConstructionCredentialKeyOverflow(t *testing.T) {
	pc := defaultBlockPolicy("")
	key := doublingBomb()
	bomb, err := json.Marshal(map[string]string{key: "README.md"})
	if err != nil {
		t.Fatal(err)
	}
	v := pc.CheckToolCallWithArgs("read_file", []string{"README.md"}, bomb)
	if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, uninspectableShellConstructionRule) {
		t.Fatalf("key overflow verdict %v %q %v", v.Matched, v.Action, v.Rules)
	}

	benign, err := json.Marshal(map[string]string{"path": "README.md"})
	if err != nil {
		t.Fatal(err)
	}
	if v := pc.CheckToolCallWithArgs("read_file", []string{"README.md"}, benign); v.Matched {
		t.Fatalf("README key matched: %q %v", v.Action, v.Rules)
	}

	secret, err := json.Marshal(map[string]string{".ssh/id_rsa": "README.md"})
	if err != nil {
		t.Fatal(err)
	}
	v = pc.CheckToolCallWithArgs("read_file", []string{"README.md"}, secret)
	if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, "Credential File Access") {
		t.Fatalf("key path verdict %v %q %v", v.Matched, v.Action, v.Rules)
	}

	pub := pc.CheckToolCall("read_file", []string{"/home/user/.ssh/id_rsa.pub"})
	if pub.Matched {
		t.Fatalf("public key matched: %q %v", pub.Action, pub.Rules)
	}
}

func TestShellConstructionOverflowViewsMatch(t *testing.T) {
	pat := regexp.MustCompile(`\bno-such-command\b`)
	clean := argView{tokens: []string{"echo", "ok"}, joined: "echo ok"}
	partial := clean
	partial.overflow = true
	if matched, _ := matchArgViews(pat, clean); matched {
		t.Fatal("clean view matched")
	}
	if matched, _ := matchArgViews(pat, clean, partial); !matched {
		t.Fatal("matchArgViews passed an overflowing view as clean")
	}
	if matched, _ := matchArgViewSet(pat, nil, clean, partial); !matched {
		t.Fatal("matchArgViewSet passed an overflowing view as clean")
	}
	if !viewsOverflow([]argView{partial}) || viewsOverflow([]argView{clean}) {
		t.Fatal("viewsOverflow misreports the set flag")
	}
}

// A value that names itself reads the earlier value, as the shell does. It is
// not a cycle, so a PATH extension is allowed and a split command name still
// resolves through the earlier assignment.
func TestShellConstructionSelfReferenceReadsEarlierValue(t *testing.T) {
	for _, cmd := range []string{
		"export PATH=" + d + "PATH:/usr/local/go/bin && go build ./...",
		"PATH=" + d + "PATH:/opt/bin; echo hi",
		"X=" + d + "X-suffix; echo " + d + "X",
	} {
		if _, _, fits := resolveShellConstruction(cmd); !fits {
			t.Errorf("%q did not finish", cmd)
		}
		if v := defaultBlockPolicy("").CheckToolCall("bash", []string{cmd}); v.Matched {
			t.Errorf("%q blocked: %v", cmd, v.Rules)
		}
	}
	split := "X=r; X=" + d + "{X}m; " + d + "X -rf /tmp/target"
	v := defaultBlockPolicy("").CheckToolCall("bash", []string{split})
	if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, ruleFileDelete) {
		t.Fatalf("split name: %v %q %v", v.Matched, v.Action, v.Rules)
	}
}

// Bash runs these. Each one builds rm from assignments the previous reader
// dropped: a newline, a loop or function body, a conditional or pipeline
// that does not run, a backslash-newline, an empty IFS, or one level of
// ${!name}.
func TestShellConstructionReadsWhatBashRuns(t *testing.T) {
	pc := defaultBlockPolicy("")
	cases := []string{
		"A=r\nB=m\n" + d + "A" + d + "B -rf /tmp/target",
		"for i in 1 2; do " + d + "A" + d + "B -rf /tmp/target; A=r; B=m; done",
		"for i in 1 2; do " + d + "A -rf /tmp/target; A=rm; done",
		"while :; do " + d + "A -rf /tmp/target; A=rm; break; done",
		"f() { " + d + "A" + d + "B -rf /tmp/target; }; A=r; B=m; f",
		"f() { A=r; B=" + d + "{A}m; " + d + "B -rf /tmp/target; }",
		"A=r;B=m;false && A=.;false && B=.;" + d + "A" + d + "B -rf /tmp/target",
		"A=rm;false && A=ls;" + d + "A -rf /tmp/target",
		"A=rm;A=ls | cat;" + d + "A -rf /tmp/target",
		"A=rm; if false; then A=ls; fi; " + d + "A -rf /tmp/target",
		"A=r\\\n;B=m\\\n;" + d + "A" + d + "B -rf /tmp/target",
		"IFS=; CMD=r" + d + "{IFS}m; " + d + "CMD -rf /tmp/target",
		"v=X; false && v=Y; X=rm; Y=ls; " + d + "{!v} -rf /tmp/target",
		"(A=r;B=m;" + d + "A" + d + "B -rf /tmp/target)",
		"function f { " + d + "A" + d + "B -rf /tmp/target; }; A=r; B=m; f",
		"for i in 1 2; do\n" + d + "A" + d + "B -rf /tmp/target\nA=r\nB=m\ndone",
		"export A=r\nexport B=m\n" + d + "A" + d + "B -rf /tmp/target",
		"declare A=r; declare B=m; " + d + "{A}" + d + "{B} -rf /tmp/target",
		"A=rm; true || A=ls; " + d + "A -rf /tmp/target",
		"IFS=\nCMD=r" + d + "{IFS}m\n" + d + "CMD -rf /tmp/target",
		"r\\\nm -rf /tmp/target",
		"A=r # keep\nB=m # keep\n" + d + "A" + d + "B -rf /tmp/target",
		"A=r; A+=m; " + d + "A -rf /tmp/target",
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			assertFileDelete(t, pc, cmd)
		})
	}
}

// Bash keeps an assignment when the rest of the simple command is only
// redirections, and export, declare, typeset, local and readonly assign
// even when another operand follows. The command name is split across two
// variables so a literal program name cannot satisfy the rule on its own.
func TestShellConstructionReadsRedirectAndBuiltinAssignments(t *testing.T) {
	pc := defaultBlockPolicy("")
	use := d + "A" + d + "B -rf /tmp/target"
	cases := []string{
		"A=r >/tmp/x; B=m; " + use,
		"A=r>/tmp/x; B=m; " + use,
		"A=r 2>/tmp/x; B=m; " + use,
		"A=r >&2; B=m; " + use,
		"A=r <>/tmp/x; B=m; " + use,
		"A=r >|/tmp/x; B=m; " + use,
		"A=r <<<text; B=m; " + use,
		"A=r <<EOF\nEOF\nB=m; " + use,
		"! A=r >/tmp/x; B=m; " + use,
		"export A=r B=m dummy; " + use,
		"export -n B=m extra; A=r; " + use,
		"declare -x B=m extra; A=r; " + use,
		"typeset B=m extra; A=r; " + use,
		"readonly B=m extra; A=r; " + use,
		"A=r B=m >/tmp/x; " + use,
		"A=r >/tmp/x B=m; " + use,
		"X=r {myfd}>/tmp/x; X=" + d + "{X}m; " + d + "X -rf /tmp/target",
		"f(){ local A=r B=m extra; " + use + "; }",
		"command export B=m extra; A=r; " + use,
		"builtin declare B=m extra; A=r; " + use,
		"command -p export B=m extra; A=r; " + use,
		"time export B=m extra; A=r; " + use,
		"! export B=m extra; A=r; " + use,
		"if true; then export B=m extra; fi; A=r; " + use,
		"{ export B=m extra; }; A=r; " + use,
		">/tmp/x export B=m extra; A=r; " + use,
		"X=r; X+=m >/tmp/x; " + d + "X -rf /tmp/target",
		"IFS=, >/tmp/x; CMD=r,m; " + d + "CMD -rf /tmp/target",
		"IFS=,; CMD=r,m >/tmp/x; " + d + "CMD -rf /tmp/target",
		"export B=m \\\n extra; A=r; " + use,
		"A=r " + d + "u; B=m; " + use,
		"A=r " + d + "{u}; B=m; " + use,
		"A=r " + d + "(true); B=m; " + use,
		"A=r >/tmp/x " + d + "(true); B=m; " + use,
		"A=r `true`; B=m; " + use,
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			assertFileDelete(t, pc, cmd)
		})
	}
}

// These assignments do not survive the command in bash. Reading them would
// block a command the shell does not run.
func TestShellConstructionPrefixRedirectIsNotAnAssignment(t *testing.T) {
	pc := defaultBlockPolicy("")
	use := d + "A" + d + "B -rf /tmp/target"
	for _, cmd := range []string{
		"A=r " + d + "u /bin/true; B=m; " + use,
		"A=r <(true); B=m; " + use,
		"A=r >(true); B=m; " + use,
		"A=r 2 >/tmp/x; B=m; " + use,
		"time A=r dummy; B=m; " + use,
		"export PATH=" + d + "PATH:/usr/bin >/tmp/build.log && go build ./...",
		"CC=gcc make >build.log",
	} {
		out, partial, fits := resolveShellConstruction(cmd)
		if !fits {
			t.Fatalf("%q did not finish (partial=%v)", cmd, partial)
		}
		if strings.Contains(out, "rm -rf") {
			t.Fatalf("%q resolved to a delete: %q", cmd, out)
		}
		if v := pc.CheckToolCall("bash", []string{cmd}); v.Matched && slices.Contains(v.Rules, ruleFileDelete) {
			t.Fatalf("%q blocked as file delete: %v", cmd, v.Rules)
		}
	}
}

// The shell is the producer. Every value it prints has to appear in the
// reading. Assignments before redirections are deliberately overread: a
// later word may have been part of a quoted target before normalization.
func TestShellConstructionRedirectValuesMatchBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX bash")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	scripts := []struct {
		script  string
		want    string
		reading string
	}{
		{`A=r >/dev/null; B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r>/dev/null; B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r 2>/dev/null; B=m; printf %s "$A$B"`, "rm", ""},
		{`export A=r B=m extra; printf %s "$A$B"`, "rm", ""},
		{`declare -x A=r B=m extra; printf %s "$A$B"`, "rm", ""},
		{`A=r >/dev/null /bin/true; B=m; printf %s "$A$B"`, "m", "rm"},
		{`A=r <(true); B=m; printf %s "$A$B"`, "m", ""},
		{`time A=r dummy; B=m; printf %s "$A$B"`, "m", ""},
		{`A=r $u; B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r ${u}; B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r $(true); B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r $u /bin/true; B=m; printf %s "$A$B"`, "m", ""},
		// sh keeps an assignment before a special builtin; bash does only in
		// POSIX mode. Either shell may run the command, so it is read as kept.
		{`A=r {fd}>/dev/null; B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r &>/dev/null; B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r >|/dev/null; B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r 2>&-; B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r <&-; B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r 3<>/dev/null; B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r 2>/dev/null >&2; B=m; printf %s "$A$B"`, "rm", ""},
		{`A=r :; B=m; printf %s "$A$B"`, "m", "rm"},
		{`A=r eval true; B=m; printf %s "$A$B"`, "m", "rm"},
	}
	for _, tc := range scripts {
		t.Run(tc.script, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
			cmd := exec.CommandContext(ctx, "bash", "-s")
			cmd.Stdin = strings.NewReader(tc.script)
			cmd.Env = []string{"PATH=/usr/bin:/bin"}
			out, err := cmd.Output()
			cancel()
			if err != nil && len(out) == 0 {
				t.Fatalf("bash: %v", err)
			}
			got := strings.TrimRight(string(out), "\n")
			if got != tc.want {
				t.Fatalf("bash printed %q, want %q", got, tc.want)
			}
			resolved, partial, fits := resolveShellConstruction(tc.script)
			if !fits || partial {
				t.Fatalf("fits=%v partial=%v out=%q", fits, partial, resolved)
			}
			reading := tc.want
			if tc.reading != "" {
				reading = tc.reading
			}
			if !strings.Contains(resolved, reading) {
				t.Fatalf("reading %q missed %q", resolved, reading)
			}
			if reading != "rm" && strings.Contains(resolved, "rm") {
				t.Fatalf("reading invented rm: %q", resolved)
			}
		})
	}
}

// Ordinary scripts stay readable. A backslash before CRLF is not a bash
// continuation, so it must not be glued into a command name.
func TestShellConstructionOrdinaryFlowAllowed(t *testing.T) {
	pc := defaultBlockPolicy("")
	for _, cmd := range []string{
		"export PATH=" + d + "PATH:/usr/local/go/bin && go build ./...",
		"export PATH=" + d + "PATH:/usr/local/go/bin\ngo build ./...",
		"PATH+=:/usr/local/go/bin && go build ./...",
		"for d in cmd internal; do echo " + d + "d; done",
		"A=ls\n" + d + "A /tmp/target",
	} {
		if _, _, fits := resolveShellConstruction(cmd); !fits {
			t.Errorf("%q did not finish", cmd)
		}
		if v := pc.CheckToolCall("bash", []string{cmd}); v.Matched {
			t.Errorf("%q blocked: %v", cmd, v.Rules)
		}
	}
	crlf := "A=r\\\r\n;B=m\\\r\n;" + d + "A" + d + "B -rf /tmp/target"
	out, _, fits := resolveShellConstruction(crlf)
	if !fits || strings.Contains(out, "rm -rf") {
		t.Fatalf("CRLF continuation joined into a command: %q fits=%v", out, fits)
	}
}

// Padding before an assembled command cannot hide it: either the command
// resolves and matches its rule, or the expansion stops and the call blocks.
// From #2230.
func TestShellConstructionBoundIsNotABypass(t *testing.T) {
	padding := "x=" + strings.Repeat("z", 1024) + ";: " + strings.Repeat(d+"x ", 70) + ";"
	cmd := padding + "a=r;b=m;" + d + "a" + d + "b -rf /tmp/target"
	for _, incomplete := range []string{"", config.ActionWarn, config.ActionBlock} {
		v := defaultBlockPolicy(incomplete).CheckToolCall("bash", []string{cmd})
		if !v.Matched || v.Action != config.ActionBlock {
			t.Fatalf("on_incomplete_check %q: verdict %v %q %v", incomplete, v.Matched, v.Action, v.Rules)
		}
	}
}

// A use reads every value its name is assigned anywhere in the text, so no
// ordering, call, trap, eval or never-run assignment can hide the one the
// shell uses.
func TestShellConstructionReadsEveryAssignedValue(t *testing.T) {
	pc := defaultBlockPolicy("")
	rm := d + "X -rf /tmp/target"
	for _, cmd := range []string{
		"X=ls; X=/bin/rm; " + rm,
		"X=/bin/rm; X=ls; " + rm,
		"X=/bin/rm; " + rm + "; X=ls;",
		"X=ls; for i in 1 2; do " + rm + "; X=/bin/rm; done",
		"f(){ X=/bin/rm; }; f; " + rm,
		"f(){ X=/bin/rm; }; X=echo; f; " + rm,
		"X=ls; f(){ X=/bin/rm; }; f; Y=" + d + "X; " + d + "Y -rf /tmp/target",
		"f(){ X=/bin/rm; }; X=echo; f; v=X; " + d + "{!v} -rf /tmp/target",
		"trap '" + rm + "' EXIT; X=/bin/rm",
		"eval '" + rm + "'; X=/bin/rm",
		"X=/bin/rm &>/dev/null; " + rm,
		"X=/bin/rm|:; " + rm,
		"X=/bin/rm & " + rm,
		// A self-reference reads each plain value, not only the last.
		"X=r; false && X=zz; X=" + d + "{X}m; " + rm,
		"X=r; false && X=" + d + "{X}z; X=" + d + "{X}m; " + rm,
		"false && X=zz; X=" + d + "{X}rm; " + rm,
		"X=r; false && X=zz; X+=m; " + rm,
		"for i in 1 2; do " + rm + "; X=" + d + "{X}m; X=r; X+=m; done",
		// An IFS assignment that never runs must not strip a flag.
		"F=-rf; false && IFS=-; rm " + d + "F /tmp/target",
		"IFS=:; IFS=,; C=r,m; " + d + "C -rf /tmp/target",
		// Several assignments on one line.
		"A=r B=m; " + d + "A" + d + "B -rf /tmp/target",
		"export A=r B=m\n" + d + "A" + d + "B -rf /tmp/target",
		// Parts with several values each.
		"A=x; B=y; A=r; B=m; " + d + "A" + d + "B -rf /tmp/target",
		"A=r; B=y; B=m; " + d + "A" + d + "B -rf /tmp/target; A=x",
		// Names that reference each other: neither has a value until one is
		// read as unset, which is how the shell starts.
		"a=r" + d + "{b}; b=" + d + "{a}m; " + d + "b -rf /tmp/target",
		// A value saved and then extended through the saved copy.
		"X=/bin/r; OLD=" + d + "X; X=" + d + "{OLD}m; " + rm,
		// A chain written last name first resolves at any depth.
		reverseChain(100) + rm,
		// A value that names another variable does not glue to the text
		// after it.
		"B=r; A=" + d + "B; X=" + d + "{A}m; " + rm,
		"B=r; X=" + d + "B; X=" + d + "{X}m; " + rm,
		"B=r; X=" + d + "B; X+=m; " + rm,
	} {
		t.Run(cmd, func(t *testing.T) {
			assertFileDelete(t, pc, cmd)
		})
	}
}

// reverseChain assigns X through depth names, each defined after the name
// that reads it.
func reverseChain(depth int) string {
	var b strings.Builder
	b.WriteString("X=" + d + "v" + strconv.Itoa(depth) + "; ")
	for i := depth; i > 1; i-- {
		b.WriteString("v" + strconv.Itoa(i) + "=" + d + "v" + strconv.Itoa(i-1) + "; ")
	}
	b.WriteString("v1=/bin/rm; ")
	return b.String()
}

// The text written for a command: one copy per value, each ended by the
// command's own separator, a pipeline kept whole, and a single-valued name
// substituted in place.
func TestResolveShellConstructionOutput(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"x=rm;" + d + "x -rf /tmp", "x=rm;rm -rf /tmp"},
		// b is unset when a=$b runs, so that assignment is also read empty.
		{"a=" + d + "b;b=rm;" + d + "a -rf", "a=rm;a=;b=rm;rm -rf"},
		{"X=a; X=b; echo " + d + "X", "X=a; X=b; echo a; echo b"},
		{"X=a; X=b; echo " + d + "X && echo done", "X=a; X=b; echo a && echo b && echo done"},
		{"X=a; X=b; echo " + d + "X | cat " + d + "X; echo done", "X=a; X=b; echo a | cat a; echo b | cat b; echo done"},
		{"X=a; X=b; echo " + d + "X 2>&1; echo done", "X=a; X=b; echo a 2>&1; echo b 2>&1; echo done"},
		{"X=a\nX=b\necho " + d + "X\necho done", "X=a\nX=b\necho a\necho b\necho done"},
		{"X=a; X=b; Y=1; Y=2; echo " + d + "X" + d + "Y", "X=a; X=b; Y=1; Y=2; echo a1; echo b1; echo a2; echo b2"},
		{"X=a; X=b; cp " + d + "X " + d + "X.bak", "X=a; X=b; cp a a.bak; cp b b.bak"},
		{"PATH=" + d + "PATH:/x; echo " + d + "PATH", "PATH=" + d + "PATH:/x; echo :/x"},
		{"A=r; A+=m; echo " + d + "A", "A=r; A+=m; echo r; echo m; echo rm"},
		{"A=r; A=" + d + "{A}m; echo " + d + "A", "A=r; A=" + d + "{A}m; echo r; echo m; echo rm"},
		{"v=IFS;" + d + "{!v}", "v=IFS;" + d + "{IFS}"},
		{"echo " + d + "HOME " + d + "{UNSET:-x}; Y=1; echo " + d + "Y", "echo " + d + "HOME " + d + "{UNSET:-x}; Y=1; echo 1"},
		{"(A=r;B=m); echo " + d + "A" + d + "B", "(A=r;B=m); echo rm; echo "},
	} {
		out, _, fits := resolveShellConstruction(tc.in)
		if !fits || out != tc.want {
			t.Errorf("%q:\n got %q fits=%v\nwant %q", tc.in, out, fits, tc.want)
		}
	}
}

// Scripts that reassign and extend variables the ordinary way finish and
// are not blocked as unfinished.
func TestShellConstructionOrdinaryScriptsFinish(t *testing.T) {
	pc := defaultBlockPolicy("")
	var accumulate strings.Builder
	accumulate.WriteString("ARGS=\n")
	for i := range 30 {
		accumulate.WriteString("ARGS=\"" + d + "ARGS --opt" + strconv.Itoa(i) + "\"\n")
	}
	accumulate.WriteString("mytool " + d + "ARGS\nmytool --check " + d + "ARGS\n")

	var appended strings.Builder
	appended.WriteString("CP=lib/core.jar\n")
	for i := range 30 {
		appended.WriteString("CP+=:lib/dep" + strconv.Itoa(i) + ".jar\n")
	}
	appended.WriteString("OUT=" + d + "OUT:build\njava -cp " + d + "CP Main " + d + "OUT\n")

	var modes strings.Builder
	for i := range 6 {
		v := "V" + strconv.Itoa(i)
		modes.WriteString("if [ -n \"" + d + "CI\" ]; then " + v + "=on; else " + v + "=off; fi\n")
	}
	modes.WriteString("mytool")
	for i := range 6 {
		modes.WriteString(" --v" + strconv.Itoa(i) + "=" + d + "V" + strconv.Itoa(i))
	}

	var sequential strings.Builder
	for i := range 40 {
		sequential.WriteString("NAME=pkg" + strconv.Itoa(i) + "\nmkdir -p out/" + d + "NAME\ncp src/" + d + "NAME.txt out/" + d + "NAME/\n")
	}

	var chain strings.Builder
	chain.WriteString("D0=/srv/app\n")
	for i := 1; i <= 40; i++ {
		chain.WriteString("D" + strconv.Itoa(i) + "=" + d + "D" + strconv.Itoa(i-1) + "/sub\n")
	}
	chain.WriteString("ls " + d + "D40\n")

	for name, cmd := range map[string]string{
		"accumulate": accumulate.String(),
		"appended":   appended.String(),
		"appended 5": "CP=lib/core.jar\nCP+=:a.jar\nCP+=:b.jar\nCP+=:c.jar\nCP+=:d.jar\nCP+=:e.jar\njava -cp " + d + "CP Main",
		"modes":      modes.String(),
		"sequential": sequential.String(),
		"chain":      chain.String(),
		"counter":    "i=0; while [ " + d + "i -lt 3 ]; do i=" + d + "((i+1)); echo " + d + "i; done",
		"swap":       "a=1; b=2; t=" + d + "a; a=" + d + "b; b=" + d + "t; echo " + d + "a " + d + "b",
		"env swap":   "t=" + d + "a; a=" + d + "b; b=" + d + "t; echo " + d + "a " + d + "b",
		"save path":  "OLD=" + d + "PATH; PATH=" + d + "{OLD}:/opt/bin; go build ./...; PATH=" + d + "OLD",
		"restore":    "old=" + d + "IFS; IFS=,; echo " + d + "IFS; IFS=" + d + "old",
	} {
		out, partial, fits := resolveShellConstruction(cmd)
		if !fits {
			t.Errorf("%s: did not finish", name)
		}
		// Only the script that appends thirty times, giving one use dozens
		// of long values, needs more copies than the budget.
		if partial != (name == "appended") {
			t.Errorf("%s: partial=%v", name, partial)
		}
		if grown := len(out) - len(cmd); grown > shellCopyBudget(len(cmd))+len(cmd) {
			t.Errorf("%s: grew %d bytes", name, grown)
		}
		// A long script can still report an incomplete check, as it does
		// without any assignment; it must not block.
		if v := pc.CheckToolCall("bash", []string{cmd}); v.Action == config.ActionBlock {
			t.Errorf("%s: blocked %v", name, v.Rules)
		}
	}
}

// A script that repeats a command for each value of a name, as an unrolled
// loop does, gets each command and value once, not once per repetition.
func TestShellConstructionRepeatedCommandCopiedOnce(t *testing.T) {
	var b strings.Builder
	for i := range 40 {
		b.WriteString("NAME=pkg" + strconv.Itoa(i) + "\nmkdir -p out/" + d + "NAME\n")
	}
	in := b.String()
	out, partial, fits := resolveShellConstruction(in)
	if !fits || partial {
		t.Fatalf("fits=%v partial=%v", fits, partial)
	}
	for i := range 40 {
		if n := strings.Count(out, "mkdir -p out/pkg"+strconv.Itoa(i)+"\n"); n < 1 || (i > 0 && n > 1) {
			t.Fatalf("pkg%d written %d times", i, n)
		}
	}
	if len(out) > 3*len(in) {
		t.Fatalf("%d bytes read as %d", len(in), len(out))
	}
	// The value that matters is still read in every command that uses it.
	hidden := in + "NAME=../../etc\nrm -rf out/" + d + "NAME\n"
	assertFileDelete(t, defaultBlockPolicy(""), hidden)
}

// Names that copy each other in a ring longer than the round cap, written
// so a value moves one name per round, cannot be read all the way around.
// The reading says so.
func TestShellConstructionLongRingIsPartial(t *testing.T) {
	ring := func(n int) string {
		var b strings.Builder
		for i := n - 1; i > 0; i-- {
			b.WriteString("v" + strconv.Itoa(i) + "=" + d + "v" + strconv.Itoa(i-1) + "; ")
		}
		return b.String() + "v0=" + d + "v" + strconv.Itoa(n-1) + "; v0=x; echo " + d + "v" + strconv.Itoa(n-1)
	}
	if out, partial, fits := resolveShellConstruction(ring(maxShellCycleRounds)); !fits || partial || !strings.HasSuffix(out, "echo x") {
		t.Fatalf("ring at the cap: %q partial=%v fits=%v", out, partial, fits)
	}
	if _, partial, fits := resolveShellConstruction(ring(maxShellCycleRounds + 4)); !fits || !partial {
		t.Fatalf("ring past the cap: partial=%v fits=%v", partial, fits)
	}
}

// assertIncomplete checks that cmd is reported as an incomplete check: a
// warning by default, a block when on_incomplete_check says so, and never a
// clean result.
func assertIncomplete(t *testing.T, cmd string) {
	t.Helper()
	for incomplete, want := range map[string]string{"": config.ActionWarn, config.ActionWarn: config.ActionWarn, config.ActionBlock: config.ActionBlock} {
		v := defaultBlockPolicy(incomplete).CheckToolCall("bash", []string{cmd})
		if !v.Matched || v.Action != want || !slices.Contains(v.Rules, IncompletePairCheckRule) || len(v.IncompleteRules) == 0 {
			t.Fatalf("on_incomplete_check %q: verdict %v %q %v", incomplete, v.Matched, v.Action, v.Rules)
		}
	}
}

// A command that uses more multi-valued names than the copy budget can hold
// combinations for is read once, and reported as an incomplete check.
func TestShellConstructionManyChoicesIncomplete(t *testing.T) {
	var b strings.Builder
	n := maxShellSlotChoices + 1
	for i := range n {
		v := "V" + strconv.Itoa(i)
		b.WriteString(v + "=a; " + v + "=b; ")
	}
	b.WriteString("echo")
	for i := range n {
		b.WriteString(" " + d + "V" + strconv.Itoa(i))
	}
	cmd := b.String()
	out, partial, fits := resolveShellConstruction(cmd)
	if !fits || !partial {
		t.Fatalf("fits=%v partial=%v", fits, partial)
	}
	if !strings.HasSuffix(out, "echo"+strings.Repeat(" a", n)) {
		t.Fatalf("not read with the first values: ...%q", out[max(0, len(out)-80):])
	}
	assertIncomplete(t, cmd)
}

// Many values of one name, each use needing a copy per value, do not fit
// the copy budget. The text is read with the first value, stays near its
// own size, and is reported as an incomplete check, so padding a name with
// values cannot make a command read as clean.
func TestShellConstructionPastCopyBudgetIsIncomplete(t *testing.T) {
	var b strings.Builder
	for i := range 3000 {
		b.WriteString("X=v" + strconv.Itoa(i) + ";")
	}
	b.WriteString(strings.Repeat("echo "+d+"X;", 2000))
	in := b.String()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	out, partial, fits := resolveShellConstruction(in)
	runtime.ReadMemStats(&after)
	if !fits || !partial {
		t.Fatalf("fits=%v partial=%v", fits, partial)
	}
	if grown := len(out) - len(in); grown > shellCopyBudget(len(in)) {
		t.Fatalf("output grew %d bytes, copy budget %d", grown, shellCopyBudget(len(in)))
	}
	limit := maxShellConstructionLen(len(in))
	const maxAllocPerLimit = 64
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc/maxAllocPerLimit > uint64(max(limit, 0)) {
		t.Fatalf("allocated %d bytes for limit %d", alloc, limit)
	}

	// The same decoy, within the budget and past it.
	decoy := "X=ls; X=/bin/rm; " + d + "X -rf /tmp/target"
	assertFileDelete(t, defaultBlockPolicy(""), decoy)
	var padded strings.Builder
	padded.WriteString("X=ls; ")
	for i := range 400 {
		padded.WriteString("X=v" + strconv.Itoa(i) + "; ")
	}
	padded.WriteString("X=/bin/rm; " + strings.Repeat("echo "+d+"X; ", 40) + d + "X -rf /tmp/target")
	if _, partial, fits := resolveShellConstruction(padded.String()); !fits || !partial {
		t.Fatalf("padded decoy fits=%v partial=%v", fits, partial)
	}
	assertIncomplete(t, padded.String())

	// A name with one value needs no copies, so other names' values cannot
	// use up its reading.
	single := padded.String() + "; Y=/bin/rm; " + d + "Y -rf /tmp/target"
	assertFileDelete(t, defaultBlockPolicy(""), single)
}

// simpleAssignRef is the assignment grammar assignSpansIn scans for, as a
// regular expression. The scanner replaced it because it is linear and this
// is not fast on dense input; the two must find the same assignments.
var simpleAssignRef = regexp.MustCompile(`(\w+)(\+?=)([^\s;&|]*)(?:[ \t]+#[^\n]*)?\s*(?:;|&&?|\|\|?|\n|$)`)

func TestAssignSpansMatchReferenceGrammar(t *testing.T) {
	type span struct {
		name                          string
		opStart, valueStart, valueEnd int
		appends                       bool
	}
	reference := func(s string) []span {
		var out []span
		for _, ix := range simpleAssignRef.FindAllStringSubmatchIndex(s, -1) {
			if ix[2] > 0 && s[ix[2]-1] == '$' {
				continue
			}
			end := ix[7]
			for end > ix[6] && s[end-1] == ')' && strings.Count(s[ix[6]:end], "(") < strings.Count(s[ix[6]:end], ")") {
				end--
			}
			out = append(out, span{s[ix[2]:ix[3]], ix[4], ix[6], end, s[ix[4]:ix[5]] == "+="})
		}
		return out
	}
	scanned := func(s string) []span {
		var out []span
		for _, a := range assignSpansIn(s, nil) {
			// The grammar has no way to say "ended by the next
			// assignment", or by a redirection or an expansion. Those are
			// checked by the cases that block.
			if !a.chained && !a.soft {
				out = append(out, span{a.name, a.opStart, a.valueStart, a.valueEnd, a.appends})
			}
		}
		return out
	}
	check := func(s string) {
		if want, got := reference(s), scanned(s); !slices.Equal(want, got) {
			t.Fatalf("%q:\n got %v\nwant %v", s, got, want)
		}
	}
	for _, s := range []string{
		"", "a=", "a=b", "a=b;", "a=b c", "a=b\nc", "a=b \n c", "a=b # c\nd", "a=b #c", "a+=b&&c", "a=b||c", "a=b|c", "a=b&c",
		"$a=b;", "$a=$b=$c=;", "(a=b)", "(a=b);c=d)", "a=$(b);", "a=b=c d", "a=b=c;", "x a=1 b=2 c", "x a=1 b=2\n", "a=b\t\n\n  c",
		"--flag=v;", "a==b;", "1=2;", "a=b)x;", "a=))((;", "a=# x\n",
	} {
		check(s)
	}
	// D=1 is the environment of cmd and is skipped.
	chained := assignSpansIn("export A=r B=m C+=x; D=1 cmd; E=2", nil)
	if len(chained) != 4 || !chained[0].chained || !chained[1].chained || chained[2].chained || chained[2].name != "C" || chained[3].name != "E" {
		t.Fatalf("assignments on one line: %+v", chained)
	}
	// Every string of these pieces up to a fixed length, in a fixed order.
	pieces := []string{"a", "B1", "=", "+=", " ", "\t", "\n", ";", "&", "|", "#", "$", "(", ")", "x"}
	var walk func(prefix string, depth int)
	walk = func(prefix string, depth int) {
		check(prefix)
		if depth == 0 {
			return
		}
		for _, p := range pieces {
			walk(prefix+p, depth-1)
		}
	}
	walk("", 4)
	// Longer strings from the same pieces, from a fixed seed.
	rng := testRand(2230)
	for range 10000 {
		var b strings.Builder
		for range 5 + rng.IntN(12) {
			b.WriteString(pieces[rng.IntN(len(pieces))])
		}
		check(b.String())
	}
}

// A line whose expansion stopped early is a partial reading. It must not be
// used to drop a short-option reading, or to show a word is not git.
func TestShellConstructionPartialReadingProvesNothing(t *testing.T) {
	var short string
	for token := range crossLineShortReadings {
		short = token
		break
	}
	expanded := []string{"tool", short}
	n := argViewNorms[0]
	whole := dropCrossLineShortReadings([]string{"tool a\ntool b"}, n, expanded, false)
	if slices.Contains(whole, short) {
		t.Fatalf("control: %q survived lines that do not produce it", short)
	}
	partial := dropCrossLineShortReadings([]string{"tool a\n" + doublingBomb()}, n, expanded, false)
	if !slices.Equal(partial, expanded) {
		t.Fatalf("partial line dropped a reading: %v", partial)
	}
	if viewsReadGit("ls") {
		t.Fatal("control: ls read as git")
	}
	if !viewsReadGit(doublingBomb()) {
		t.Fatal("partial reading treated as not git")
	}
}

// The reader's claim, checked against the shell itself: whatever order,
// loop, function, conditional or pipeline a script puts plain assignments
// in, every value bash gives a use is one the reader wrote out. The scripts
// only echo. Values a script extends are left out; how far those are
// followed is covered above.
func TestShellConstructionReadsWhatBashPrints(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX bash")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	rng := testRand(2229)
	names := []string{"A", "B", "C"}
	values := []string{"r", "m", "x", "-f", "zz"}
	pick := func(list []string) string { return list[rng.IntN(len(list))] }
	statement := func() string {
		i := rng.IntN(len(names))
		n := names[i]
		switch rng.IntN(9) {
		case 0, 1:
			return n + "=" + pick(values)
		case 2:
			return "false && " + n + "=" + pick(values)
		case 3:
			return "true && " + n + "=" + pick(values)
		case 4:
			return "false || " + n + "=" + pick(values)
		case 5:
			if rng.IntN(2) == 0 {
				return "export " + n + "=" + pick(values) + " " + pick(names) + "=" + pick(values)
			}
			return n + "=" + pick(values) + " | cat"
		case 6, 7:
			// A value built from another name, always an earlier one in
			// names, so no value grows by passing through itself.
			if i == 0 {
				return n + "=" + pick(values)
			}
			return n + "=" + d + "{" + names[rng.IntN(i)] + "}" + pick(values)
		default:
			return "echo [" + d + pick(names) + d + pick(names) + "]"
		}
	}
	skipped := 0
	for range 400 {
		var parts []string
		for range 2 + rng.IntN(6) {
			parts = append(parts, statement())
		}
		body := strings.Join(parts, "; ") + "; echo [" + d + "A" + d + "B" + d + "C]"
		script := body
		switch rng.IntN(5) {
		case 0:
			script = "for i in 1 2 3; do " + body + "; done"
		case 1:
			script = "f(){ " + body + "; }; f; f"
		case 2:
			script = "f(){ " + body + "; }; " + pick(names) + "=" + pick(values) + "; f"
		case 3:
			script = "trap '" + body + "' EXIT; " + pick(names) + "=" + pick(values)
		}
		script = "A=a; B=b; C=c; " + script
		ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(10*time.Second))
		cmd := exec.CommandContext(ctx, "bash", "-s")
		cmd.Stdin = strings.NewReader(script)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		printed, err := cmd.Output()
		cancel()
		if err != nil {
			t.Fatalf("bash failed on %q: %v", script, err)
		}
		read, partial, fits := resolveShellConstruction(script)
		if !fits {
			t.Fatalf("%q did not finish", script)
		}
		if partial {
			// More combinations than the copy budget: reported incomplete,
			// not claimed complete.
			skipped++
			continue
		}
		for _, line := range strings.Fields(string(printed)) {
			if !strings.Contains(read, line) {
				t.Fatalf("%q\nbash printed %s\nreader wrote %q", script, line, read)
			}
		}
	}
	if skipped > 40 {
		t.Fatalf("%d of 400 scripts were past the copy budget", skipped)
	}
}

// An assignment the nesting scan skips over, inside quoted text or a
// comment, is read as conditional rather than certain.
func TestShellConditionalAtMarksSkippedText(t *testing.T) {
	for _, tc := range []struct {
		s  string
		at int
	}{
		{"echo 'Z=1'; true", strings.Index("echo 'Z=1'; true", "=")},
		{"echo \"Z=1\"; true", strings.Index("echo \"Z=1\"; true", "=")},
		{"true # Z=1\ntrue", strings.Index("true # Z=1\ntrue", "=")},
	} {
		if out, _ := shellConditionalAt(tc.s, []int{tc.at}); !out[tc.at] {
			t.Errorf("%q: assignment at %d read as certain", tc.s, tc.at)
		}
	}
	if out, _ := shellConditionalAt("Z=1; true", []int{1}); out[1] {
		t.Errorf("plain assignment read as conditional")
	}

	// "#" after ")" or "}" may or may not start a comment. The reading is
	// marked incomplete, the same path as a full copy budget.
	for _, cmd := range []string{
		"if test -f /nope; then (:)#; fi\nZ=echo\nfi; A=r; B=m; " + d + "Z" + d + "A" + d + "B -rf /tmp/target",
		"if test -f /nope; then echo " + d + "(true)# fi\nZ=echo\nfi; A=r; B=m; " + d + "Z" + d + "A" + d + "B -rf /tmp/target",
		"echo " + d + "{x}#; Z=1; echo " + d + "Z",
		"echo " + d + "{x}#; if test -f /nope; then\nZ=echo\nfi; A=r; B=m; " + d + "Z" + d + "A" + d + "B -rf /tmp/target",
	} {
		if _, partial, fits := resolveShellConstruction(cmd); !fits || !partial {
			t.Errorf("%q: partial=%v fits=%v, want an incomplete reading", cmd, partial, fits)
		}
	}
}
