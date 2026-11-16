package policy

import (
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Chained assignments whose values name other assigned variables used to
// re-expand on every iteration of resolveShellConstruction, so a 482-byte
// command allocated multi-gigabyte strings and the process was OOM-killed.
func TestResolveShellConstructionBoundsGrowth(t *testing.T) {
	d := "$"
	inputs := []string{
		"echo '" + d + "a=" + d + "b=" + d + "c=;'",
		"echo '" + d + "a=" + d + "b=" + d + "c=" + d + "d=" + d + "e=" + d + "f=;'",
		"awk '{printf \"pid=%s \", " + d + "1; " + d + "1=" + d + "2=" + d + "3=\"\"; print substr(" + d + "0,1,150)}'",
		"x=" + d + "x" + d + "x;" + d + "x;" + d + "x;" + d + "x",
	}
	for _, in := range inputs {
		out, _ := resolveShellConstruction(in)
		if limit := 64 << 10; len(out) > limit {
			t.Errorf("input %q expanded to %d bytes, want <= %d", in, len(out), limit)
		}
	}
}

// The bound must not weaken the evasion detection the expansion exists for.
func TestResolveShellConstructionStillExpands(t *testing.T) {
	d := "$"
	cases := map[string]string{
		"x=rm;" + d + "x -rf /":              "rm -rf /",
		"x=rm;" + d + "{x} -rf /":            "rm -rf /",
		"IFS=,;CMD=r,m;" + d + "CMD -rf /":   "rm -rf /",
		d + "(printf rm) -rf /":              "rm -rf /",
		"a=r;b=" + d + "a;" + d + "{b}m -rf": "rm -rf",
	}
	for in, want := range cases {
		out, complete := resolveShellConstruction(in)
		if !strings.Contains(out, want) || !complete {
			t.Errorf("resolveShellConstruction(%q) = %q complete=%v, want it to contain %q", in, out, complete, want)
		}
	}
}

// boundPadding is a large variable expanded often enough to pass the bound.
func boundPadding() string {
	return "x=" + strings.Repeat("z", 1024) + ";: " + strings.Repeat("$x ", 70) + ";"
}

// A replacement skipped at the bound must not stop the others: a command
// assembled from small variables after the padding still resolves, and the
// result reports that it is incomplete.
func TestResolveShellConstructionSkipsOnlyOversizedReplacement(t *testing.T) {
	out, complete := resolveShellConstruction(boundPadding() + "a=r;b=m;$a$b -rf /tmp/target")
	if complete {
		t.Fatal("over-bound expansion reported complete")
	}
	if !strings.Contains(out, "rm -rf /tmp/target") {
		t.Fatalf("command after the padding was not resolved: ...%q", out[max(0, len(out)-60):])
	}
}

// Padding that passes the bound must not let an assembled command through.
// The command still matches its rule, and a command that does not resolve
// reports an incomplete check, as an unreadable word reading does.
func TestShellConstructionBoundIsNotABypass(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	v := pc.CheckToolCall("bash", []string{boundPadding() + "a=r;b=m;$a$b -rf /tmp/target"})
	if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, ruleFileDelete) {
		t.Fatalf("assembled rm -rf after padding: verdict %v %q %v", v.Matched, v.Action, v.Rules)
	}

	// The skipped variable itself carries the command name.
	hidden := "x=/" + strings.Repeat("./", 600) + "bin/rm;: " + strings.Repeat("$x ", 70) + ";$x -rf /tmp/target"
	for _, tt := range []struct{ incomplete, want string }{
		{"", config.ActionWarn},
		{config.ActionBlock, config.ActionBlock},
	} {
		pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, OnIncompleteCheck: tt.incomplete, Rules: DefaultToolPolicyRules()})
		v := pc.CheckToolCall("bash", []string{hidden})
		if !v.Matched || v.Action != tt.want {
			t.Fatalf("on_incomplete_check %q: verdict %v %q %v incomplete %v", tt.incomplete, v.Matched, v.Action, v.Rules, v.IncompleteRules)
		}
	}
}
