// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// This file never spells the YAML step key next to its colon, so its own
// fixtures are not picked up when the real-tree test scans tracked files.
const (
	actionPinUsesWord = "uses"
	actionPinUsesKey  = actionPinUsesWord + ":"
	// actionPinFixtureFile holds deliberate fake pins for the release-doc
	// version checker. It is the only tracked file the scan skips.
	actionPinFixtureFile = "scripts/test_release_doc_versions.py"
)

// actionPinOwners are the official owners of the pipelock action, compared
// case-insensitively. Any other owner fails the check.
var actionPinOwners = []string{"luckypipewrench", "pipelab-org"}

// actionPinUsesKeyPattern finds a step key at line start or after whitespace,
// a flow-mapping brace or comma, an inline-code backtick, or a quote. Keys such
// as x-uses do not match. A space before the colon is allowed, as in YAML.
var actionPinUsesKeyPattern = regexp.MustCompile("(?i)(?:^|[\\s{,`\"'\\[])" + actionPinUsesWord + `\s*:`)

// actionPinRefPattern parses <owner>/pipelock@<ref> at the start of a step
// value. The ref stops at whitespace, quotes, Markdown and flow punctuation,
// and comments. Reusable-workflow subpaths, local "./" actions and other
// actions do not match.
var actionPinRefPattern = regexp.MustCompile("(?i)^([^\\s/\"'`{}\\[\\](),#]+)/pipelock@([^\\s\"'`{}\\[\\](),#]*)")

// actionPinBlockHeader is a YAML block-scalar header (>, >-, |, |+2 ...).
var actionPinBlockHeader = regexp.MustCompile(`^[>|][1-9+-]{0,2}\s*(?:#.*)?$`)

var fullCommitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// actionPinRequiredFiles must each carry at least one pinned copy, so a
// refactor that drops or rewrites one of them cannot quietly pass. Comment
// labels next to the pins (# v3.7.0 ...) are checked by
// scripts/release_doc_versions.py, not here.
var actionPinRequiredFiles = []string{
	"README.md",
	"docs/guides/suppression.md",
	"examples/ci-workflow.yaml",
	"examples/ci-workflow-advanced.yaml",
	".github/workflows/reusable-scan.yml",
}

var errNotGitCheckout = errors.New("not inside a git checkout")

type actionPin struct {
	Path     string
	Line     int
	Owner    string
	Ref      string
	Unparsed string // non-empty when a step value names pipelock but cannot be parsed
}

func (p actionPin) String() string {
	if p.Unparsed != "" {
		return fmt.Sprintf("%s:%d unparsed %q", p.Path, p.Line, p.Unparsed)
	}
	return fmt.Sprintf("%s:%d %s/pipelock@%s", p.Path, p.Line, p.Owner, p.Ref)
}

// actionPinStepValue returns the value of the step key ending at valueStart on
// line index i, following an anchor (&name) and a block-scalar header or an
// empty value onto the next non-blank line. It also returns the 1-based line
// the value sits on.
func actionPinStepValue(lines []string, i int, value string) (string, int) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "&") {
		_, rest, _ := strings.Cut(value, " ")
		value = strings.TrimSpace(rest)
	}
	if value != "" && !actionPinBlockHeader.MatchString(value) {
		return value, i + 1
	}
	for j := i + 1; j < len(lines); j++ {
		if next := strings.TrimSpace(lines[j]); next != "" {
			return next, j + 1
		}
	}
	return "", i + 1
}

func unquoteActionPinValue(value string) string {
	if value == "" || (value[0] != '"' && value[0] != '\'') {
		return value
	}
	body := value[1:]
	if end := strings.IndexByte(body, value[0]); end >= 0 {
		return body[:end]
	}
	return body
}

func findActionPins(rel, content string) []actionPin {
	var pins []actionPin
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		keys := actionPinUsesKeyPattern.FindAllStringIndex(line, -1)
		for k, loc := range keys {
			end := len(line)
			if k+1 < len(keys) {
				end = keys[k+1][0]
			}
			value, lineNo := actionPinStepValue(lines, i, line[loc[1]:end])
			value = unquoteActionPinValue(value)
			if m := actionPinRefPattern.FindStringSubmatch(value); m != nil {
				pins = append(pins, actionPin{Path: rel, Line: lineNo, Owner: m[1], Ref: m[2]})
				continue
			}
			if strings.Contains(strings.ToLower(value), "pipelock@") {
				pins = append(pins, actionPin{Path: rel, Line: lineNo, Unparsed: value})
			}
		}
	}
	return pins
}

// actionPinProblem returns why one pin is invalid on its own, or "".
func actionPinProblem(p actionPin) string {
	switch {
	case p.Unparsed != "":
		return fmt.Sprintf("%s:%d: cannot parse pipelock action ref %q; write it as <owner>/pipelock@<40-hex SHA>", p.Path, p.Line, p.Unparsed)
	case !slices.Contains(actionPinOwners, strings.ToLower(p.Owner)):
		return fmt.Sprintf("%s:%d: owner %q is not an official pipelock owner (%s)", p.Path, p.Line, p.Owner, strings.Join(actionPinOwners, ", "))
	case !fullCommitSHA.MatchString(p.Ref):
		return fmt.Sprintf("%s:%d: %q is not a full 40-hex commit SHA", p.Path, p.Line, p.Ref)
	}
	return ""
}

// checkActionPinParity returns every reason the pins disagree. An empty result
// means at least one copy exists, every required file has one, every copy uses
// an official owner and a full 40-hex commit SHA, and all copies share it.
func checkActionPinParity(pins []actionPin, required []string) []string {
	if len(pins) == 0 {
		return []string{"no pipelock action pins found"}
	}
	var problems []string
	for _, rel := range required {
		if !slices.ContainsFunc(pins, func(p actionPin) bool { return p.Path == rel }) {
			problems = append(problems, fmt.Sprintf("%s: no pipelock action pin found", rel))
		}
	}
	shas := map[string]bool{}
	for _, p := range pins {
		if problem := actionPinProblem(p); problem != "" {
			problems = append(problems, problem)
			continue
		}
		shas[strings.ToLower(p.Ref)] = true
	}
	if len(shas) > 1 {
		var b strings.Builder
		fmt.Fprintf(&b, "pipelock action pins disagree (%d distinct SHAs):", len(shas))
		for _, p := range pins {
			fmt.Fprintf(&b, "\n  %s", p)
		}
		problems = append(problems, b.String())
	}
	return problems
}

func runActionPinGit(ctx context.Context, gitBin, root string, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, gitBin, append([]string{"-C", root}, args...)...) // #nosec G204 -- fixed git subcommands on the test's own repo root or a temp fixture.
	cmd.Env = append(append(os.Environ(), "LC_ALL=C"), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s in %s: %w: %s", strings.Join(args, " "), root, err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// listActionPinTrackedFiles returns git's tracked-file list for root. It fails
// when git is missing or errors, when root is not the top level of its own
// checkout (for example a tarball unpacked inside another repository), and when
// git lists nothing. Only "root is in no git checkout at all" wraps
// errNotGitCheckout, so the caller can decide how to treat a source tarball.
func listActionPinTrackedFiles(ctx context.Context, gitBin, root string, env []string) ([]string, error) {
	if gitBin == "" {
		return nil, errors.New("git not found on PATH: the pin scan needs git ls-files")
	}
	top, err := runActionPinGit(ctx, gitBin, root, env, "rev-parse", "--show-toplevel")
	if err != nil {
		if strings.Contains(err.Error(), "not a git repository") {
			return nil, fmt.Errorf("%w: %w", errNotGitCheckout, err)
		}
		return nil, err
	}
	wantTop, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", root, err)
	}
	gotTop, err := filepath.EvalSymlinks(strings.TrimSpace(top))
	if err != nil {
		return nil, fmt.Errorf("resolve git top level %s: %w", strings.TrimSpace(top), err)
	}
	if gotTop != wantTop {
		return nil, fmt.Errorf("repo root %s is not the git top level %s (a tree inside another checkout?)", wantTop, gotTop)
	}
	out, err := runActionPinGit(ctx, gitBin, root, env, "ls-files", "-z")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, rel := range strings.Split(out, "\x00") {
		if rel != "" {
			files = append(files, rel)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("git ls-files listed no tracked files under %s", root)
	}
	return files, nil
}

// checkActionPinDiscovery fails when discovery returned nothing or omitted a
// required file; required files are never appended behind discovery's back.
func checkActionPinDiscovery(files, required []string) error {
	if len(files) == 0 {
		return errors.New("discovery returned no files")
	}
	var missing []string
	for _, rel := range required {
		if !slices.Contains(files, rel) {
			missing = append(missing, rel)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("discovery did not return required files: %s", strings.Join(missing, ", "))
	}
	return nil
}

func collectActionPins(t *testing.T, root string, files []string) []actionPin {
	t.Helper()
	var pins []actionPin
	for _, rel := range files {
		if rel == actionPinFixtureFile {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- paths come from the repo's own file list under root.
		if errors.Is(err, fs.ErrNotExist) {
			continue // tracked but deleted in the working tree
		}
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if bytes.IndexByte(b, 0) >= 0 {
			continue // binary
		}
		pins = append(pins, findActionPins(rel, string(b))...)
	}
	return pins
}

func isCIEnvironment() bool {
	return os.Getenv("CI") == "true" || os.Getenv("GITHUB_ACTIONS") == "true"
}

// TestActionPinParity keeps every copy of the pipelock GitHub Action pin in the
// docs, examples and workflows on one official owner and one commit SHA.
func TestActionPinParity(t *testing.T) {
	t.Parallel()
	root := repoRootForDocsAccuracy(t)
	for _, rel := range actionPinRequiredFiles {
		_ = readDocAccuracyFile(t, root, rel) // a missing required file fails here
	}

	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("pin parity: git not found on PATH (%v); this test scans git ls-files and must not pass without it", err)
	}
	files, err := listActionPinTrackedFiles(t.Context(), gitBin, root, nil)
	if errors.Is(err, errNotGitCheckout) && !isCIEnvironment() {
		t.Skipf("SKIPPED pin parity: %s is not a git checkout (an unpacked source tarball?), so tracked files cannot be listed. "+
			"Run from a git clone to check the pins. CI always fails here instead. Cause: %v", root, err)
	}
	if err != nil {
		t.Fatalf("pin parity: discovery failed: %v", err)
	}
	if err := checkActionPinDiscovery(files, actionPinRequiredFiles); err != nil {
		t.Fatalf("pin parity: %v", err)
	}
	// Stat the index so Go's test cache sees changes to the tracked-file list.
	if indexPath, err := runActionPinGit(t.Context(), gitBin, root, nil, "rev-parse", "--path-format=absolute", "--git-path", "index"); err == nil {
		_, _ = os.Stat(strings.TrimSpace(indexPath))
	}

	pins := collectActionPins(t, root, files)
	for _, p := range pins {
		t.Logf("pin %s", p)
	}
	if problems := checkActionPinParity(pins, actionPinRequiredFiles); len(problems) > 0 {
		t.Fatalf("pipelock action pin parity failed:\n%s", strings.Join(problems, "\n"))
	}
	t.Logf("%d tracked files scanned; %d pipelock action pins share %s", len(files), len(pins), strings.ToLower(pins[0].Ref))
}

type actionPinCase struct {
	name      string
	files     map[string]string
	wantOK    bool
	wantPins  int
	wantInErr []string
}

func actionPinFixtureSHAs() (string, string) {
	return strings.Repeat("a", 40), strings.Repeat("b", 40)
}

// actionPinStep builds a workflow step line at runtime; see actionPinUsesWord.
func actionPinStep(owner, ref string) string {
	return "      - " + actionPinUsesKey + " " + owner + "/pipelock@" + ref + " # action source\n"
}

func actionPinCheckerCases() []actionPinCase {
	shaA, shaB := actionPinFixtureSHAs()
	step := actionPinStep
	k := actionPinUsesKey
	okRequired := func(readme string) map[string]string {
		return map[string]string{
			"README.md":                  readme,
			"docs/guide.md":              step("luckyPipewrench", shaA),
			".github/workflows/scan.yml": step("pipelab-org", shaA),
		}
	}
	return []actionPinCase{
		{
			name: "positive control all match",
			files: map[string]string{
				"README.md":                  step("luckyPipewrench", shaA),
				"docs/guide.md":              step("pipelab-org", shaA) + "text\n" + step("LUCKYPIPEWRENCH", strings.ToUpper(shaA)),
				".github/workflows/scan.yml": "steps:\n  - " + k + " ./\n" + step("luckypipewrench", shaA),
			},
			wantOK:   true,
			wantPins: 4,
		},
		{
			name: "mutation one copy flipped",
			files: map[string]string{
				"README.md":                  step("luckyPipewrench", shaA),
				"docs/guide.md":              step("luckyPipewrench", shaA) + "text\n" + step("luckyPipewrench", shaB),
				".github/workflows/scan.yml": step("pipelab-org", shaA),
			},
			wantPins:  4,
			wantInErr: []string{"2 distinct SHAs", "docs/guide.md:3 luckyPipewrench/pipelock@" + shaB, "README.md:1 luckyPipewrench/pipelock@" + shaA},
		},
		{
			name: "zero copies",
			files: map[string]string{
				"README.md":                  "no pins here\n",
				"docs/guide.md":              "- " + k + " ./\n",
				".github/workflows/scan.yml": k + " luckyPipewrench/pipelock/.github/workflows/reusable-scan.yml@" + shaA + "\n",
			},
			wantInErr: []string{"no pipelock action pins found"},
		},
		{
			name:      "required file without a copy",
			files:     map[string]string{"README.md": step("luckyPipewrench", shaA), "docs/guide.md": "pin removed\n", ".github/workflows/scan.yml": step("luckyPipewrench", shaA)},
			wantPins:  2,
			wantInErr: []string{"docs/guide.md: no pipelock action pin found"},
		},
		{name: "tag instead of commit SHA", files: okRequired(step("luckyPipewrench", "v3.7.0")), wantPins: 3, wantInErr: []string{`README.md:1: "v3.7.0" is not a full 40-hex commit SHA`}},
		{name: "7-hex short SHA", files: okRequired(step("luckyPipewrench", shaA[:7])), wantPins: 3, wantInErr: []string{`README.md:1: "aaaaaaa" is not a full 40-hex commit SHA`}},
		{name: "39-hex short SHA", files: okRequired(step("luckyPipewrench", shaA[:39])), wantPins: 3, wantInErr: []string{`"` + shaA[:39] + `" is not a full 40-hex commit SHA`}},
		{name: "41-hex SHA", files: okRequired(step("luckyPipewrench", shaA+"a")), wantPins: 3, wantInErr: []string{`"` + shaA + `a" is not a full 40-hex commit SHA`}},
		{name: "40-hex plus suffix", files: okRequired(step("luckyPipewrench", shaA+"-x")), wantPins: 3, wantInErr: []string{`"` + shaA + `-x" is not a full 40-hex commit SHA`}},
		{
			name:     "quoted values match",
			files:    okRequired("- " + k + ` "luckyPipewrench/pipelock@` + shaA + `"` + "\n- " + k + ` 'pipelab-org/pipelock@` + shaA + "' # x\n"),
			wantOK:   true,
			wantPins: 4,
		},
		{
			name:      "quoted values drift",
			files:     okRequired("- " + k + ` "luckyPipewrench/pipelock@` + shaA + `"` + "\n- " + k + ` 'pipelab-org/pipelock@` + shaB + "'\n"),
			wantPins:  4,
			wantInErr: []string{"2 distinct SHAs", "README.md:2 pipelab-org/pipelock@" + shaB},
		},
		{
			name:     "two pins on one line match",
			files:    okRequired("- {" + k + " luckyPipewrench/pipelock@" + shaA + "}, {" + k + " pipelab-org/pipelock@" + shaA + "}\n"),
			wantOK:   true,
			wantPins: 4,
		},
		{
			name:      "two pins on one line second drifts",
			files:     okRequired("- {" + k + " luckyPipewrench/pipelock@" + shaA + "}, {" + k + " pipelab-org/pipelock@" + shaB + "}\n"),
			wantPins:  4,
			wantInErr: []string{"2 distinct SHAs", "README.md:1 luckyPipewrench/pipelock@" + shaA, "README.md:1 pipelab-org/pipelock@" + shaB},
		},
		{
			name:      "space before colon is checked",
			files:     okRequired(step("luckyPipewrench", shaA) + "  - " + actionPinUsesWord + " : luckyPipewrench/pipelock@" + shaB + "\n"),
			wantPins:  4,
			wantInErr: []string{"README.md:2 luckyPipewrench/pipelock@" + shaB},
		},
		{
			name:      "anchored value is checked and alias ignored",
			files:     okRequired(step("luckyPipewrench", shaA) + "  - " + k + " &pin luckyPipewrench/pipelock@" + shaB + "\n  - " + k + " *pin\n"),
			wantPins:  4,
			wantInErr: []string{"README.md:2 luckyPipewrench/pipelock@" + shaB},
		},
		{
			name:      "folded value is checked",
			files:     okRequired(step("luckyPipewrench", shaA) + "  - " + k + " >-\n      luckyPipewrench/pipelock@" + shaB + "\n"),
			wantPins:  4,
			wantInErr: []string{"README.md:3 luckyPipewrench/pipelock@" + shaB},
		},
		{
			name:     "anchored folded value matches",
			files:    okRequired("  - " + k + " &pin >-\n      luckyPipewrench/pipelock@" + shaA + "\n"),
			wantOK:   true,
			wantPins: 3,
		},
		{
			name:      "unparseable pipelock ref fails",
			files:     okRequired(step("luckyPipewrench", shaA) + "  - " + k + " ${{ env.OWNER }}/pipelock@" + shaA + "\n"),
			wantPins:  4,
			wantInErr: []string{`README.md:2: cannot parse pipelock action ref "${{ env.OWNER }}/pipelock@` + shaA + `"`},
		},
		{
			name: "markdown inline code, flow mapping and prose do not false-fail",
			files: okRequired("Add `" + k + " luckyPipewrench/pipelock@" + shaA + "` to a step.\n" +
				"steps: [{name: scan, " + k + " pipelab-org/pipelock@" + shaA + "}]\n" +
				"Never pin luckyPipewrench/pipelock@main; pin a SHA.\n" +
				"x-" + k + " luckyPipewrench/pipelock@" + shaB + "\n" +
				"image: ghcr.io/luckypipewrench/pipelock@sha256:" + shaB + shaB[:24] + "\n"),
			wantOK:   true,
			wantPins: 4,
		},
		{
			name:      "unofficial owner fails",
			files:     okRequired(step("evil-fork", shaA)),
			wantPins:  3,
			wantInErr: []string{`README.md:1: owner "evil-fork" is not an official pipelock owner`},
		},
		{
			name: "only the release-doc fixture file is skipped",
			files: map[string]string{
				"README.md":                  step("luckyPipewrench", shaA),
				"docs/guide.md":              step("luckyPipewrench", shaA),
				".github/workflows/scan.yml": step("luckyPipewrench", shaA),
				actionPinFixtureFile:         step("luckyPipewrench", shaB),
			},
			wantOK:   true,
			wantPins: 3,
		},
		{
			name: "other tests, testdata and changelog are scanned",
			files: map[string]string{
				"README.md":                  step("luckyPipewrench", shaA),
				"docs/guide.md":              step("luckyPipewrench", shaA),
				".github/workflows/scan.yml": step("luckyPipewrench", shaA),
				"scripts/test_other.py":      step("luckyPipewrench", shaB),
				"internal/pkg/pin_test.go":   step("luckyPipewrench", shaB),
				"internal/pkg/testdata/x.md": step("luckyPipewrench", shaB),
				"CHANGELOG.md":               step("luckyPipewrench", shaB),
			},
			wantPins:  7,
			wantInErr: []string{"2 distinct SHAs", "scripts/test_other.py:1", "internal/pkg/pin_test.go:1", "internal/pkg/testdata/x.md:1", "CHANGELOG.md:1"},
		},
	}
}

func TestCheckActionPinParity(t *testing.T) {
	t.Parallel()
	required := []string{"README.md", "docs/guide.md", ".github/workflows/scan.yml"}
	for _, tt := range actionPinCheckerCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root, files := writeActionPinFixtures(t, tt.files)
			pins := collectActionPins(t, root, files)
			if len(pins) != tt.wantPins {
				t.Fatalf("got %d pins %v, want %d", len(pins), pins, tt.wantPins)
			}
			assertActionPinProblems(t, checkActionPinParity(pins, required), tt.wantOK, tt.wantInErr)
		})
	}
}

// TestActionPinDiscovery runs discovery against real temp git repositories, so
// a regression in the tracked-file scan cannot hide behind the required files.
func TestActionPinDiscovery(t *testing.T) {
	t.Parallel()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("git not found on PATH (%v); discovery fixtures need it", err)
	}
	shaA, shaB := actionPinFixtureSHAs()
	required := []string{"README.md", "docs/guide.md"}
	base := map[string]string{"README.md": actionPinStep("luckyPipewrench", shaA), "docs/guide.md": actionPinStep("pipelab-org", shaA)}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{}
		for _, m := range []map[string]string{base, extra} {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}

	tests := []struct {
		name      string
		tracked   map[string]string
		untracked map[string]string
		layout    string // "", "foreign" (root inside another repo), "plain" (no repo)
		gitBin    string
		env       []string
		wantErr   string
		notRepo   bool
		wantOK    bool
		wantInErr []string
	}{
		{name: "discovered-only file matches", tracked: with(map[string]string{"docs/extra/other.md": actionPinStep("luckyPipewrench", shaA)}), wantOK: true},
		{name: "discovered-only file drifts", tracked: with(map[string]string{"docs/extra/other.md": actionPinStep("luckyPipewrench", shaB)}), wantInErr: []string{"2 distinct SHAs", "docs/extra/other.md:1 luckyPipewrench/pipelock@" + shaB}},
		{name: "untracked and vendored files are not scanned", tracked: base, untracked: map[string]string{"node_modules/x/README.md": actionPinStep("luckyPipewrench", "v3.5.0"), "notes.md": actionPinStep("luckyPipewrench", shaB)}, wantOK: true},
		{name: "required file untracked", tracked: map[string]string{"README.md": base["README.md"]}, untracked: map[string]string{"docs/guide.md": base["docs/guide.md"]}, wantErr: "discovery did not return required files: docs/guide.md"},
		{name: "empty index", untracked: base, wantErr: "git ls-files listed no tracked files"},
		{name: "index file missing", tracked: base, env: []string{"GIT_INDEX_FILE=/nonexistent/pipelock-index"}, wantErr: "git ls-files listed no tracked files"},
		{name: "tree inside another checkout", untracked: base, layout: "foreign", wantErr: "is not the git top level"},
		{name: "not a git checkout", untracked: base, layout: "plain", wantErr: "not a git repository", notRepo: true},
		{name: "git missing", tracked: base, gitBin: "-", wantErr: "git not found on PATH"},
		{name: "git fails", tracked: base, gitBin: "/nonexistent/git", wantErr: "git rev-parse --show-toplevel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			outer := t.TempDir()
			env := []string{"GIT_CEILING_DIRECTORIES=" + filepath.Dir(outer), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
			root := outer
			switch tt.layout {
			case "foreign":
				gitActionPinFixture(t, gitBin, outer, env, "init", "-q")
				root = filepath.Join(outer, "unpacked")
			case "":
				gitActionPinFixture(t, gitBin, root, env, "init", "-q")
			}
			writeActionPinFilesAt(t, root, tt.untracked)
			if len(tt.tracked) > 0 {
				names := writeActionPinFilesAt(t, root, tt.tracked)
				gitActionPinFixture(t, gitBin, root, env, append([]string{"add", "--"}, names...)...)
			}
			bin := gitBin
			switch tt.gitBin {
			case "-":
				bin = ""
			case "":
			default:
				bin = tt.gitBin
			}

			files, err := listActionPinTrackedFiles(t.Context(), bin, root, append(env, tt.env...))
			if err == nil {
				err = checkActionPinDiscovery(files, required)
			}
			if tt.wantErr != "" {
				assertActionPinDiscoveryErr(t, err, tt.wantErr, tt.notRepo)
				return
			}
			if err != nil {
				t.Fatalf("discovery: %v", err)
			}
			pins := collectActionPins(t, root, files)
			assertActionPinProblems(t, checkActionPinParity(pins, required), tt.wantOK, tt.wantInErr)
		})
	}
}

func assertActionPinDiscoveryErr(t *testing.T, err error, want string, notRepo bool) {
	t.Helper()
	if err == nil {
		t.Fatalf("want discovery error containing %q, got none", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("discovery error %q, want it to contain %q", err, want)
	}
	if got := errors.Is(err, errNotGitCheckout); got != notRepo {
		t.Fatalf("errors.Is(err, errNotGitCheckout) = %v, want %v (err: %v)", got, notRepo, err)
	}
}

func gitActionPinFixture(t *testing.T, gitBin, dir string, env []string, args ...string) {
	t.Helper()
	if _, err := runActionPinGit(t.Context(), gitBin, dir, env, args...); err != nil {
		t.Fatalf("fixture: %v", err)
	}
}

func writeActionPinFilesAt(t *testing.T, root string, contents map[string]string) []string {
	t.Helper()
	files := make([]string, 0, len(contents))
	for rel, content := range contents {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
		files = append(files, rel)
	}
	slices.Sort(files)
	return files
}

func writeActionPinFixtures(t *testing.T, contents map[string]string) (string, []string) {
	t.Helper()
	root := t.TempDir()
	return root, writeActionPinFilesAt(t, root, contents)
}

func assertActionPinProblems(t *testing.T, problems []string, wantOK bool, wantInErr []string) {
	t.Helper()
	joined := strings.Join(problems, "\n")
	if wantOK {
		if len(problems) != 0 {
			t.Fatalf("want parity, got problems:\n%s", joined)
		}
		return
	}
	if len(problems) == 0 {
		t.Fatal("want parity failure, got none")
	}
	for _, want := range wantInErr {
		if !strings.Contains(joined, want) {
			t.Errorf("problems missing %q:\n%s", want, joined)
		}
	}
}
