// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

const containCLIDoc = "../../../docs/contain-cli.md"

// doctorDocSection returns the `pipelock contain doctor` section of the
// contain CLI reference.
func doctorDocSection(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(containCLIDoc)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	start := strings.Index(doc, "## `pipelock contain doctor`")
	if start < 0 {
		t.Fatal("contain doctor section not found")
	}
	section := doc[start+1:]
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	return section
}

var doctorDocCheckRow = regexp.MustCompile("(?m)^\\| (\\d+) \\| `([a-z_]+)`( \\(conditional\\))? \\|")

// The documented doctor check table must list exactly the checks the doctor
// can run, with the same numbers and names, and mark as conditional exactly
// the checks that run only for some configurations.
func TestContainDoctorCheckTableMatchesDocs(t *testing.T) {
	documented := map[int]string{}
	documentedConditional := map[int]bool{}
	for _, m := range doctorDocCheckRow.FindAllStringSubmatch(doctorDocSection(t), -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := documented[n]; dup {
			t.Fatalf("check %d documented twice (%s, %s)", n, prev, m[2])
		}
		documented[n] = m[2]
		documentedConditional[n] = m[3] != ""
	}

	// Enable every conditional check: an xvnc display and an agent home.
	cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("containment:\n  display:\n    enabled: true\n    backend: xvnc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	always := map[int]bool{}
	for _, c := range allDoctorChecks() {
		always[c.n] = true
	}
	code := map[int]string{}
	for _, c := range doctorChecksForEnv(&doctorEnv{configPath: cfgPath, agentHome: "/home/agent"}) {
		code[c.n] = c.name
	}
	if len(code) == len(always) {
		t.Fatal("fixture enabled no conditional doctor checks")
	}

	for n, name := range code {
		if documented[n] != name {
			t.Errorf("doctor check %d %q is documented as %q", n, name, documented[n])
		}
		if documentedConditional[n] == always[n] {
			t.Errorf("doctor check %d %q: documented conditional=%v, runs unconditionally=%v", n, name, documentedConditional[n], always[n])
		}
	}
	for n, name := range documented {
		if _, ok := code[n]; !ok {
			t.Errorf("docs list doctor check %d %q, which the doctor cannot run", n, name)
		}
	}
}

var doctorDocExitSentence = regexp.MustCompile(`Exit code is (\d) if every check passed, (\d) if any check failed, and (\d) if`)

// The documented doctor exit codes must be the ones the command returns.
func TestContainDoctorExitCodesMatchDocs(t *testing.T) {
	m := doctorDocExitSentence.FindStringSubmatch(strings.Join(strings.Fields(doctorDocSection(t)), " "))
	if m == nil {
		t.Fatal("doctor exit-code sentence not found")
	}
	for i, want := range []int{cliutil.ExitOK, cliutil.ExitGeneral, cliutil.ExitConfig} {
		if got, _ := strconv.Atoi(m[i+1]); got != want {
			t.Errorf("documented exit code %d is %d, command returns %d", i, got, want)
		}
	}
}
