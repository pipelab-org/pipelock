// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// selectorLayout is one way an operator can spell --workspace. build lays out
// the filesystem and returns the selector. Directory g holds the control files
// the baseline was recorded from; directory d holds different ones and is the
// place a mis-resolved spelling would silently observe.
type selectorLayout struct {
	name string
	// refused spellings must exit nonzero in both modes, with a remedy the
	// operator can act on. Accepted spellings must observe the directory the
	// kernel opens for the same text.
	refused bool
	build   func(t *testing.T, p string) (selector string)
	// swap, when set, runs after a baseline was recorded under the selector's own
	// spelling, so it can change what that spelling opens.
	swap func(t *testing.T, p string)
}

// reportedWorkspace returns the workspace an audit or record named in its output.
func reportedWorkspace(t *testing.T, out string, jsonOutput bool) string {
	t.Helper()
	if jsonOutput {
		var results []controlAuditResult
		if err := json.Unmarshal([]byte(out), &results); err != nil || len(results) != 1 {
			t.Fatalf("audit JSON: %v\n%s", err, out)
		}
		return results[0].Workspace
	}
	for _, line := range strings.Split(out, "\n") {
		for _, prefix := range []string{"Workspace ", "Recorded workspace control baseline for "} {
			if quoted, ok := strings.CutPrefix(line, prefix); ok {
				path, err := strconv.Unquote(quoted)
				if err != nil {
					t.Fatalf("unquote %q: %v", quoted, err)
				}
				return path
			}
		}
	}
	t.Fatalf("no workspace named in output:\n%s", out)
	return ""
}

func sameDirectory(t *testing.T, a, b string) bool {
	t.Helper()
	ia, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	ib, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(ia, ib)
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestControlAuditSelectorMatrix pins the invariant behind PR2-6 and PR2-9: no
// spelling of --workspace may pass while observing a directory other than the
// one the kernel opens for that text. A refused spelling must say what to do.
func TestControlAuditSelectorMatrix(t *testing.T) {
	const before, other = "before", "DIFFERENT"
	mkdir := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	link := func(t *testing.T, target, name string) {
		t.Helper()
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	layouts := []selectorLayout{
		{name: "G/.", build: func(t *testing.T, p string) string { return filepath.Join(p, "g") + "/." }},
		{name: "G/./", build: func(t *testing.T, p string) string { return filepath.Join(p, "g") + "/./" }},
		{name: "G//", build: func(t *testing.T, p string) string { return filepath.Join(p, "g") + "//" }},
		{name: "G/ (trailing slash)", build: func(t *testing.T, p string) string { return filepath.Join(p, "g") + "/" }},
		{name: "//-prefixed absolute", build: func(t *testing.T, p string) string { return "/" + filepath.Join(p, "g") }},
		{name: "relative g from cwd P", build: func(t *testing.T, p string) string { t.Chdir(p); return "g" }},
		{name: "relative ./g/ from cwd P", build: func(t *testing.T, p string) string { t.Chdir(p); return "./g/" }},
		{name: "relative . from cwd G", build: func(t *testing.T, p string) string { t.Chdir(filepath.Join(p, "g")); return "." }},
		{name: "relative g, cwd through a symlink, PWD logical", refused: true, build: func(t *testing.T, p string) string {
			via := filepath.Join(canonicalTempDir(t), "via")
			link(t, p, via)
			t.Chdir(via)
			return "g"
		}},
		{name: "relative g, cwd through a symlink, PWD unset", build: func(t *testing.T, p string) string {
			via := filepath.Join(canonicalTempDir(t), "via")
			link(t, p, via)
			t.Chdir(via)
			t.Setenv("PWD", "")
			return "g"
		}},
		{name: "selector is a symlink to G", refused: true, build: func(t *testing.T, p string) string {
			link(t, filepath.Join(p, "g"), filepath.Join(p, "l"))
			return filepath.Join(p, "l")
		}},
		{name: "selector is a symlink to G, trailing slash", refused: true, build: func(t *testing.T, p string) string {
			link(t, filepath.Join(p, "g"), filepath.Join(p, "l"))
			return filepath.Join(p, "l") + "/"
		}},
		{name: "selector is a symlink to D", refused: true, build: func(t *testing.T, p string) string {
			link(t, filepath.Join(p, "d"), filepath.Join(p, "l"))
			return filepath.Join(p, "l")
		}},
		{name: "G after its parent became a symlink to D's parent", refused: true, build: func(t *testing.T, p string) string {
			writeAuditFixture(t, filepath.Join(p, "par", "g"), ".envrc", before)
			writeAuditFixture(t, filepath.Join(p, "elsewhere", "g"), ".envrc", other)
			return filepath.Join(p, "par", "g")
		}, swap: func(t *testing.T, p string) {
			if err := os.Rename(filepath.Join(p, "par"), filepath.Join(p, "par.real")); err != nil {
				t.Fatal(err)
			}
			link(t, filepath.Join(p, "elsewhere"), filepath.Join(p, "par"))
		}},
		{name: "G after its parent became a symlink to the moved original", refused: true, build: func(t *testing.T, p string) string {
			writeAuditFixture(t, filepath.Join(p, "par", "g"), ".envrc", before)
			return filepath.Join(p, "par", "g")
		}, swap: func(t *testing.T, p string) {
			if err := os.Rename(filepath.Join(p, "par"), filepath.Join(p, "par.real")); err != nil {
				t.Fatal(err)
			}
			link(t, filepath.Join(p, "par.real"), filepath.Join(p, "par"))
		}},
		{name: "G/sub/.. (dot-dot after a real directory)", refused: true, build: func(t *testing.T, p string) string {
			mkdir(t, filepath.Join(p, "g", "sub"))
			return filepath.Join(p, "g", "sub") + "/.."
		}},
		{name: "link/../g (dot-dot after a symlink)", refused: true, build: func(t *testing.T, p string) string {
			mkdir(t, filepath.Join(p, "far", "sub"))
			link(t, filepath.Join(p, "far", "sub"), filepath.Join(p, "link"))
			return filepath.Join(p, "link") + "/../g"
		}},
		{name: "relative ../g from a sibling cwd", refused: true, build: func(t *testing.T, p string) string {
			mkdir(t, filepath.Join(p, "sib"))
			t.Chdir(filepath.Join(p, "sib"))
			return "../g"
		}},
	}
	type row struct{ spelling, record, audit, observed, verdict string }
	var table []row
	for _, tc := range layouts {
		t.Run(tc.name, func(t *testing.T) {
			p := canonicalTempDir(t)
			g, d := filepath.Join(p, "g"), filepath.Join(p, "d")
			writeAuditFixture(t, g, ".envrc", before)
			writeAuditFixture(t, d, ".envrc", other)
			recorded, _ := controlAuditFixture(t)
			if err := os.MkdirAll(filepath.Dir(recorded.store.path), 0o750); err != nil {
				t.Fatal(err)
			}
			// Baseline for G, spelled canonically, in the store the audit reads.
			_, _ = runAuditFixture(t, recorded, controlAuditOptions{workspace: g, record: true}, 0)

			sel := tc.build(t, p)
			if tc.swap != nil {
				_, _ = runAuditFixture(t, recorded, controlAuditOptions{workspace: sel, record: true}, 0)
				tc.swap(t, p)
			}
			// A fresh store for --record, so the spelling's own key is not preempted.
			fresh, _ := controlAuditFixture(t)

			var recOut, audOut bytes.Buffer
			recErr := fresh.run(&recOut, controlAuditOptions{workspace: sel, record: true})
			audErr := recorded.run(&audOut, controlAuditOptions{workspace: sel, json: true})
			exit := func(err error) int {
				if err == nil {
					return 0
				}
				return cliutil.ExitCodeOf(err)
			}
			rc, ac := exit(recErr), exit(audErr)
			observed := "-"
			verdict := "refused"

			if tc.refused {
				if rc == 0 || ac == 0 {
					t.Fatalf("%q must be refused: record exit %d, audit exit %d\n%s\n%s", sel, rc, ac, recOut.String(), audOut.String())
				}
				for _, err := range []error{recErr, audErr} {
					if err == nil || !strings.Contains(err.Error(), "pipelock") && !strings.Contains(err.Error(), "pass the path") {
						t.Fatalf("%q: refusal gives no remedy: %v", sel, err)
					}
				}
			} else {
				if rc != 0 || ac != 0 {
					t.Fatalf("%q must be accepted: record exit %d (%v), audit exit %d (%v)\n%s\n%s", sel, rc, recErr, ac, audErr, recOut.String(), audOut.String())
				}
				// Whatever was reported must be the directory the kernel opens for
				// this text, and the audit must have compared against G.
				for _, rep := range []struct {
					out  string
					json bool
				}{{recOut.String(), false}, {audOut.String(), true}} {
					if got := reportedWorkspace(t, rep.out, rep.json); !sameDirectory(t, got, sel) {
						t.Fatalf("%q: observed %q, which is not the directory the kernel opens", sel, got)
					}
				}
				if !sameDirectory(t, reportedWorkspace(t, audOut.String(), true), g) {
					t.Fatalf("%q: audit passed while observing a directory other than the baseline's", sel)
				}
				observed, verdict = "G", "ok"
			}
			table = append(table, row{tc.name, strconv.Itoa(rc), strconv.Itoa(ac), observed, verdict})
		})
	}
	var b strings.Builder
	for _, r := range table {
		fmt.Fprintf(&b, "%-58s record=%s audit=%s observed=%s %s\n", r.spelling, r.record, r.audit, r.observed, r.verdict)
	}
	t.Logf("selector matrix:\n%s", b.String())
}

// The workspace inventory is JSON, and encoding/json writes and reads an invalid
// UTF-8 byte as U+FFFD. A grant on a directory with such a name is therefore
// stored as a different, valid path. Two grants that differed only in those
// bytes collapse into one, and an unrelated directory literally named with
// U+FFFD would be audited, and recorded clean, in place of the granted one.
func TestControlAuditAgentRefusesGrantPathsTheInventoryCouldNotStoreExactly(t *testing.T) {
	p := canonicalTempDir(t)
	granted, other := filepath.Join(p, "g\xff"), filepath.Join(p, "g\xfe")
	decoy := filepath.Join(p, "g�")
	writeAuditFixture(t, granted, ".envrc", "granted")
	writeAuditFixture(t, other, ".envrc", "granted too")
	writeAuditFixture(t, decoy, ".envrc", "unrelated")
	const agent = "pipelock-agent"
	// The inventory is read as the file holds it: raw bytes where the operator's
	// directory names had them, or the replacement character json.Marshal wrote.
	for name, body := range map[string]string{
		"raw bytes":    fmt.Sprintf(`{"workspaces":[{"path":%q,"agent_user":%q},{"path":%q,"agent_user":%q}]}`, granted, agent, other, agent),
		"as marshaled": `{"workspaces":[{"path":"` + decoy + `","agent_user":"` + agent + `"}]}`,
	} {
		if name == "raw bytes" {
			// %q escapes the byte as \xff, which is not JSON; write it raw.
			body = `{"workspaces":[{"path":"` + granted + `","agent_user":"` + agent + `"},{"path":"` + other + `","agent_user":"` + agent + `"}]}`
		}
		t.Run(name, func(t *testing.T) {
			env, _ := controlAuditFixture(t)
			env.readInventory = func(string) ([]byte, error) { return []byte(body), nil }
			for _, record := range []bool{true, false} {
				out, err := runAuditFixture(t, env, controlAuditOptions{agentUser: agent, record: record}, 1)
				if !strings.Contains(err.Error(), "U+FFFD") || strings.Contains(out, "workspace_control_surface=clean") {
					t.Fatalf("record=%t: a grant the inventory cannot name exactly was audited: %v\n%s", record, err, out)
				}
			}
		})
	}
}

// --workspace takes the bytes the shell passed, so a name that is not valid
// UTF-8 keeps its own baseline and is not confused with a sibling whose name
// differs only in those bytes or with one spelled with U+FFFD.
func TestControlAuditWorkspaceKeepsNonUTF8NamesApart(t *testing.T) {
	env, _ := controlAuditFixture(t)
	p := canonicalTempDir(t)
	a, b, c := filepath.Join(p, "g\xff"), filepath.Join(p, "g\xfe"), filepath.Join(p, "g�")
	for _, dir := range []string{a, b, c} {
		writeAuditFixture(t, dir, ".envrc", "same")
	}
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: a, record: true}, 0)
	writeAuditFixture(t, b, ".envrc", "changed")
	writeAuditFixture(t, c, ".envrc", "changed")
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: a}, 0)
	for _, other := range []string{b, c} {
		out, _ := runAuditFixture(t, env, controlAuditOptions{workspace: other}, 2)
		if !strings.Contains(out, "missing_baseline") {
			t.Fatalf("%q read another directory's baseline: %s", other, out)
		}
	}
}
