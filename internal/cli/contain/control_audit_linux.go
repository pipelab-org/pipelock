// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/workspacediff"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

type controlAuditEnv struct {
	store         controlAuditStore
	inventory     string
	readInventory func(string) ([]byte, error)
	euid          func() int
	budget        workspacediff.ControlSurfaceBudget
}

type controlAuditResult struct {
	Workspace string `json:"workspace"`
	Status    string `json:"workspace_control_surface"`
	Reason    string `json:"reason,omitempty"`
	Remedy    string `json:"remedy,omitempty"`
	*workspacediff.ControlSurfaceStatement
}

func runControlAudit(w io.Writer, opts controlAuditOptions) error {
	env := controlAuditEnv{
		store:     controlAuditStore{path: filepath.Join(defaultControlAuditDir, "control-audit")},
		inventory: defaultWorkspaceInvPath, readInventory: os.ReadFile, euid: os.Geteuid,
		budget: workspacediff.DefaultControlSurfaceBudget(),
	}
	return env.run(w, opts)
}

// run reports the outcome through w. A report that could not be written is an
// I/O failure, exit 1, whatever the observation found: an operator who never saw
// the findings has not been shown a passing audit.
func (env controlAuditEnv) run(w io.Writer, opts controlAuditOptions) error {
	out := &auditReportWriter{w: w}
	err := env.runTo(out, opts)
	if out.err != nil {
		return fmt.Errorf("write audit report: %w; retry sudo pipelock contain audit-workspace %s", out.err, auditRetryArgs(opts))
	}
	return err
}

// auditReportWriter keeps the first error from writing the report, which the
// formatters otherwise discard.
type auditReportWriter struct {
	w   io.Writer
	err error
}

func (a *auditReportWriter) Write(p []byte) (int, error) {
	if a.err != nil {
		return 0, a.err
	}
	n, err := a.w.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	a.err = err
	return n, err
}

func (env controlAuditEnv) runTo(w io.Writer, opts controlAuditOptions) error {
	if env.euid() != 0 {
		return fmt.Errorf("audit-workspace requires root; rerun with sudo pipelock contain audit-workspace %s", auditRetryArgs(opts))
	}
	roots, err := env.roots(opts)
	if err != nil {
		return fmt.Errorf("select workspace: %w; run sudo pipelock contain list-workspaces", err)
	}
	dir, err := env.store.open(opts.record)
	if err != nil && (opts.record || !errors.Is(err, os.ErrNotExist)) {
		return fmt.Errorf("open control baseline store: %w; inspect the directory chain with sudo namei -l %s", err, auditShellArg(env.store.path))
	}
	if dir != nil {
		defer func() { _ = dir.Close() }()
	}
	if opts.record {
		if err := unix.Flock(int(dir.Fd()), unix.LOCK_EX); err != nil {
			return fmt.Errorf("lock control baseline store: %w; retry sudo pipelock contain audit-workspace --record %s", err, auditSelector(opts))
		}
		return env.record(w, dir, roots, opts.replace)
	}
	return env.audit(w, dir, roots, opts)
}

func auditRetryArgs(opts controlAuditOptions) string {
	args := auditSelector(opts)
	if opts.record {
		args += " --record"
	}
	if opts.replace {
		args += " --replace"
	}
	// A retry must ask for the same report and accept the same findings, or the
	// pasted command can change the outcome it was meant to repeat.
	if opts.json {
		args += " --json"
	}
	if opts.allowChanges {
		args += " --allow-control-surface-changes"
	}
	if opts.allowPartial {
		args += " --allow-partial-nested-discovery"
	}
	return args
}

func auditSelector(opts controlAuditOptions) string {
	if opts.workspace != "" {
		return "--workspace " + auditShellArg(opts.workspace)
	}
	return "--agent-user " + auditShellArg(opts.agentUser)
}

func (env controlAuditEnv) roots(opts controlAuditOptions) ([]string, error) {
	var paths []string
	if opts.agentUser != "" {
		inv, err := loadWorkspaceInventoryFrom(env.readInventory, env.inventory)
		if err != nil {
			return nil, err
		}
		for _, grant := range grantsForAgent(inv.Workspaces, opts.agentUser) {
			if !filepath.IsAbs(grant.Path) || filepath.Clean(grant.Path) != grant.Path {
				return nil, fmt.Errorf("invalid workspace grant path %q", grant.Path)
			}
			paths = append(paths, grant.Path)
		}
		if len(paths) == 0 {
			return nil, fmt.Errorf("no workspace grants for %q", opts.agentUser)
		}
		slices.Sort(paths)
		return slices.Compact(paths), nil
	}
	// The lexical grant path is the baseline key. Resolving a caller's
	// selector here could silently select a different workspace's baseline.
	// Cleaning also drops a ".." together with the component before it, and
	// after a symbolic link the kernel leaves the link's target instead, so a
	// path spelled that way would audit a workspace other than the one named.
	if slices.Contains(strings.Split(filepath.ToSlash(opts.workspace), "/"), "..") {
		return nil, fmt.Errorf("workspace path %q contains \"..\", which names a different directory when a link precedes it; pass the path without it", opts.workspace)
	}
	abs, err := filepath.Abs(opts.workspace)
	if err != nil {
		return nil, err
	}
	return []string{abs}, nil
}

// Check the grant path without changing the baseline key. A missing root
// is left to the snapshotter so it can be reported as incomplete.
func checkAuditRoot(root string) error {
	resolved, err := filepath.EvalSymlinks(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		// A PathError prints the failing path unescaped, and that path can be
		// an intermediate a link target chose. Report only the cause.
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return fmt.Errorf("inspect workspace path %q: %w", root, err)
	}
	// The resolved path comes from link targets the agent may have chosen, so it
	// is shown escaped and never offered as text to paste into a shell.
	if resolved != root {
		return fmt.Errorf("workspace path %q resolves to %q through a symbolic link; baselines are keyed by the path as given, so pass the resolved path or the path sudo pipelock contain list-workspaces shows for the grant, or restore the layout the baseline was recorded under", root, resolved)
	}
	return nil
}

func (env controlAuditEnv) record(w io.Writer, dir *os.File, roots []string, replace bool) error {
	pending := make(map[string]workspacediff.ControlSurfaceSnapshot, len(roots))
	var kept []string
	incomplete := false
	for _, root := range roots {
		old, err := env.store.load(dir, root)
		existing := err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return env.baselineError(root, err)
		}
		if existing && !replace {
			return fmt.Errorf("baseline already exists for %q; after reviewing the workspace run %s", root, recordRemedy(root, true))
		}
		capBytes := int64(defaultWorkspaceDiffCapBytes)
		if existing {
			capBytes = old.CapBytes()
		}
		if err := checkAuditRoot(root); err != nil {
			return err
		}
		current, err := workspacediff.SnapshotControlSurface(root, capBytes, env.budget)
		if err != nil {
			return fmt.Errorf("snapshot %q: %w; retry %s", root, err, recordRemedy(root, replace))
		}
		health, err := workspacediff.CompareControlBaseline(current, current)
		if err != nil {
			return err
		}
		if existing {
			diff, err := workspacediff.CompareControlBaseline(old, current)
			if err != nil {
				return err
			}
			var preview bytes.Buffer
			_, _ = fmt.Fprintf(&preview, "Replacing workspace control baseline for %q\n", root)
			printWorkspaceControls(&preview, map[string]workspacediff.ControlSurfaceStatement{root: diff})
			if _, err := preview.WriteTo(w); err != nil {
				return fmt.Errorf("write replacement diff: %w; retry %s", err, recordRemedy(root, true))
			}
		}
		if health.Incomplete || health.NestedDiscoveryPartial {
			incomplete = true
			printWorkspaceControls(w, map[string]workspacediff.ControlSurfaceStatement{root: health})
			if !health.Incomplete {
				// Recording again cannot widen discovery; the audit flag is the control.
				_, _ = fmt.Fprintf(w, "Audits of this workspace report partial nested discovery until it is accepted with --allow-partial-nested-discovery\n")
			} else {
				_, _ = fmt.Fprintf(w, "Resolve the observation issue, then run %s\n", recordRemedy(root, true))
			}
			// A complete baseline is the evidence the next replacement is
			// reviewed against. An incomplete observation cannot stand in for
			// it: after one, the preview would no longer show what changed.
			if existing && health.Incomplete {
				prior, err := workspacediff.CompareControlBaseline(old, old)
				if err != nil {
					return err
				}
				if !prior.Incomplete {
					_, _ = fmt.Fprintf(w, "Kept the existing complete baseline for %q\n", root)
					kept = append(kept, root)
					continue
				}
			}
		}
		pending[root] = current
	}
	for _, root := range roots {
		if _, ok := pending[root]; !ok {
			continue
		}
		if err := writeControlBaseline(dir, root, pending[root], replace); err != nil {
			return fmt.Errorf("save baseline for %q: %w; review the store and retry %s", root, err, recordRemedy(root, replace))
		}
		_, _ = fmt.Fprintf(w, "Recorded workspace control baseline for %q\n", root)
	}
	if len(kept) > 0 {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("kept the existing complete baseline for %q because the new observation is incomplete", kept))
	}
	if incomplete {
		return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("recorded baseline has incomplete or partial observations"))
	}
	return nil
}

func (env controlAuditEnv) audit(w io.Writer, dir *os.File, roots []string, opts controlAuditOptions) error {
	results := make([]controlAuditResult, 0, len(roots))
	blocked := false
	var auditErrors []error
	for _, root := range roots {
		result, err := env.auditOne(dir, root, opts)
		if err != nil {
			auditErrors = append(auditErrors, err)
			results = append(results, controlAuditResult{
				Workspace: root, Status: workspaceControlUnavailable, Reason: "audit_error", Remedy: err.Error(),
			})
			continue
		}
		blocked = blocked || auditResultBlocked(result, opts)
		results = append(results, result)
	}
	if opts.json {
		if err := json.NewEncoder(w).Encode(results); err != nil {
			return fmt.Errorf("write audit JSON: %w; retry sudo pipelock contain audit-workspace --json %s", err, auditSelector(opts))
		}
	} else {
		for _, result := range results {
			_, _ = fmt.Fprintf(w, "Workspace %q\n", result.Workspace)
			if result.ControlSurfaceStatement != nil {
				printWorkspaceControls(w, map[string]workspacediff.ControlSurfaceStatement{result.Workspace: *result.ControlSurfaceStatement})
			} else {
				if result.Reason == "missing_baseline" {
					_, _ = fmt.Fprintln(w, "  [WARN] workspace control baseline is missing")
				}
				printWorkspaceControlUnavailable(w, result.Reason)
			}
			if result.Remedy != "" {
				_, _ = fmt.Fprintln(w, result.Remedy)
			}
		}
	}
	if err := errors.Join(auditErrors...); err != nil {
		return err
	}
	if blocked {
		return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("workspace control surface audit did not pass"))
	}
	return nil
}

func (env controlAuditEnv) auditOne(dir *os.File, root string, opts controlAuditOptions) (controlAuditResult, error) {
	if err := checkAuditRoot(root); err != nil {
		return controlAuditResult{}, err
	}
	if dir == nil {
		return missingControlBaseline(root), nil
	}
	before, err := env.store.load(dir, root)
	if errors.Is(err, os.ErrNotExist) {
		return missingControlBaseline(root), nil
	}
	if err != nil {
		return controlAuditResult{}, env.baselineError(root, err)
	}
	current, err := workspacediff.SnapshotControlSurface(root, before.CapBytes(), env.budget)
	if err != nil {
		return controlAuditResult{}, fmt.Errorf("snapshot %q: %w; retry sudo pipelock contain audit-workspace --workspace %s", root, err, auditShellArg(root))
	}
	diff, err := workspacediff.CompareControlBaseline(before, current)
	if err != nil {
		return controlAuditResult{}, env.baselineError(root, err)
	}
	result := controlAuditResult{Workspace: root, Status: workspaceControlStatus(diff.Changed, diff.Incomplete, diff.NestedDiscoveryPartial), ControlSurfaceStatement: &diff}
	if diff.Incomplete || diff.Changed || diff.NestedDiscoveryPartial {
		result.Remedy = "After reviewing the findings, resolve any observation issue and run " + recordRemedy(root, true)
		if !diff.Incomplete && auditResultBlocked(result, opts) {
			flags := []string{}
			if diff.Changed || opts.allowChanges {
				flags = append(flags, "--allow-control-surface-changes")
			}
			if diff.NestedDiscoveryPartial || opts.allowPartial {
				flags = append(flags, "--allow-partial-nested-discovery")
			}
			result.Remedy += " or rerun with sudo pipelock contain audit-workspace --workspace " + auditShellArg(root) + " " + strings.Join(flags, " ")
		}
	}
	return result, nil
}

func missingControlBaseline(root string) controlAuditResult {
	return controlAuditResult{Workspace: root, Status: workspaceControlUnavailable, Reason: "missing_baseline", Remedy: "Review the workspace, then run " + recordRemedy(root, false)}
}

func auditResultBlocked(result controlAuditResult, opts controlAuditOptions) bool {
	s := result.ControlSurfaceStatement
	return s == nil || s.Incomplete || (s.Changed && !opts.allowChanges) || (s.NestedDiscoveryPartial && !opts.allowPartial)
}

func recordRemedy(root string, replace bool) string {
	command := "sudo pipelock contain audit-workspace --record"
	if replace {
		command += " --replace"
	}
	return command + " --workspace " + auditShellArg(root)
}

func (env controlAuditEnv) baselineError(root string, err error) error {
	file := filepath.Join(env.store.path, controlBaselineFilename(root))
	return fmt.Errorf("read baseline for %q: %w; inspect with sudo namei -l %s, move an invalid baseline aside after review, then run %s", root, err, auditShellArg(file), recordRemedy(root, false))
}

// auditShellArg quotes s for a remedy the operator may paste into a shell. A
// path can come from link targets or names an agent chose, so control
// characters and invalid UTF-8 are written as escapes in bash's $'...' form
// rather than printed raw, where they could rewrite the operator's terminal.
func auditShellArg(s string) string {
	printable := utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) == -1
	if printable {
		return shellQuote(s)
	}
	var b strings.Builder
	b.WriteString("$'")
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1, !unicode.IsPrint(r):
			for _, c := range []byte(s[i : i+size]) {
				_, _ = fmt.Fprintf(&b, "\\x%02x", c)
			}
		case r == '\'' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	b.WriteByte('\'')
	return b.String()
}
