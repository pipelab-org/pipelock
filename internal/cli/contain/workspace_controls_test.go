// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/workspacediff"
)

// A workspace whose control paths could not be observed at either end of the
// session, or whose two snapshots cannot be compared, is reported incomplete
// with the cause. It never reads as a clean result.
func TestCompareWorkspaceControlsReportsFailedObservations(t *testing.T) {
	const root = "/workspace"
	observed, err := workspacediff.SnapshotControlSurface(t.TempDir(), 1<<20, workspacediff.DefaultControlSurfaceBudget())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		before, after controlSurfaceObservation
		want          string
	}{
		{"start failed", controlSurfaceObservation{err: errors.New("start broke")}, controlSurfaceObservation{snapshot: observed}, "session-start snapshot: start broke"},
		{"end failed", controlSurfaceObservation{snapshot: observed}, controlSurfaceObservation{err: errors.New("end broke")}, "session-end snapshot: end broke"},
		{"snapshots that do not compare", controlSurfaceObservation{}, controlSurfaceObservation{snapshot: observed}, "incompatible control surface snapshots"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := compareWorkspaceControls(
				map[string]controlSurfaceObservation{root: tc.before},
				map[string]controlSurfaceObservation{root: tc.after},
			)[root]
			if !got.Incomplete || got.Changed || !strings.Contains(got.IncompleteReason, tc.want) {
				t.Fatalf("want an incomplete result naming %q without a change claim, got %+v", tc.want, got)
			}
		})
	}
}
