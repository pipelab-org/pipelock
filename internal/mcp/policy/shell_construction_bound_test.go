package policy

import (
	"strings"
	"testing"
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
		out := resolveShellConstruction(in)
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
		if out := resolveShellConstruction(in); !strings.Contains(out, want) {
			t.Errorf("resolveShellConstruction(%q) = %q, want it to contain %q", in, out, want)
		}
	}
}
