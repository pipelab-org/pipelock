// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/workspacediff"
)

type controlSurfaceObservation struct {
	snapshot workspacediff.ControlSurfaceSnapshot
	err      error
}

func snapshotWorkspaceControls(grants []workspaceGrant, capBytes int64) map[string]controlSurfaceObservation {
	out := make(map[string]controlSurfaceObservation, len(grants))
	for _, g := range grants {
		if _, seen := out[g.Path]; !seen {
			snapshot, err := workspacediff.SnapshotControlSurface(g.Path, capBytes, workspacediff.DefaultControlSurfaceBudget())
			out[g.Path] = controlSurfaceObservation{snapshot: snapshot, err: err}
		}
	}
	return out
}

func compareWorkspaceControls(before, after map[string]controlSurfaceObservation) map[string]workspacediff.ControlSurfaceStatement {
	out := make(map[string]workspacediff.ControlSurfaceStatement, len(before))
	for root, start := range before {
		end := after[root]
		var result workspacediff.ControlSurfaceStatement
		switch {
		case start.err != nil:
			result.IncompleteReason = fmt.Sprintf("session-start snapshot: %v", start.err)
		case end.err != nil:
			result.IncompleteReason = fmt.Sprintf("session-end snapshot: %v", end.err)
		default:
			var err error
			result, err = workspacediff.DiffControlSurface(start.snapshot, end.snapshot)
			if err != nil {
				result.IncompleteReason = err.Error()
			}
		}
		result.Incomplete = result.IncompleteReason != ""
		out[root] = result
	}
	return out
}

func printWorkspaceControls(w io.Writer, results map[string]workspacediff.ControlSurfaceStatement) string {
	if len(results) == 0 {
		return ""
	}
	var paths, reasons []string
	for root, result := range results {
		for _, path := range result.Paths() {
			paths = append(paths, filepath.Join(root, path))
		}
		if result.Incomplete {
			reasons = append(reasons, fmt.Sprintf("%s: %s", root, result.IncompleteReason))
		}
	}
	slices.Sort(paths)
	slices.Sort(reasons)
	paths = slices.Compact(paths)
	status := "clean"
	if len(paths) > 0 {
		status = "changed"
		_, _ = fmt.Fprintf(w, "  [WARN] workspace control paths CHANGED: %q\n", paths)
	}
	if len(reasons) > 0 {
		status = "incomplete"
		_, _ = fmt.Fprintf(w, "  [WARN] workspace control surface observation is INCOMPLETE: %q\n", reasons)
	}
	_, _ = fmt.Fprintf(w, "workspace_control_surface=%s changed=%t paths=%q reason=%q\n",
		status, len(paths) > 0, paths, strings.Join(reasons, "; "))
	return status
}
