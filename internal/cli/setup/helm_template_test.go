// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// helmBinary, helmTemplateDeadline and helmWaitDelay are variables so the tests
// below can substitute stand-ins that stall or leave the output pipe open.
var (
	helmBinary           = "helm"
	helmTemplateDeadline = testwait.Deadline(2 * time.Minute)
	// helmWaitDelay bounds how long Wait keeps reading output after helm exits
	// or the deadline kills it, in case a helm child still holds the pipe.
	helmWaitDelay = 5 * time.Second
)

// helmTemplate runs `helm template` under its own deadline. t.Context() alone
// ends only when the test does, so a helm process that never exits would hold
// the whole package until the CI job limit instead of failing this test with
// helm's output.
func helmTemplate(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), helmTemplateDeadline)
	defer cancel()
	// #nosec G204 -- fixed subcommand; callers pass fixed charts and private t.TempDir inputs.
	cmd := exec.CommandContext(ctx, helmBinary, append([]string{"template"}, args...)...)
	cmd.WaitDelay = helmWaitDelay
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("helm template %s did not finish within %s: %w", strings.Join(args, " "), helmTemplateDeadline, ctx.Err())
	}
	return out, err
}

// useStandInHelm points helmTemplate at a POSIX shell script for one test.
func useStandInHelm(t *testing.T, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stand-in helm is a POSIX shell script")
	}
	stub := filepath.Join(t.TempDir(), "helm")
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil { // #nosec G306 -- test stand-in must be executable.
		t.Fatal(err)
	}
	originalBinary := helmBinary
	helmBinary = stub
	t.Cleanup(func() { helmBinary = originalBinary })
}

func TestHelmTemplateFailsAtItsDeadline(t *testing.T) {
	useStandInHelm(t, "#!/bin/sh\necho rendering\nexec sleep 600\n")
	// The budget must cover shell startup and the echo on a contended host, or
	// the deadline can kill the stand-in before it writes anything.
	originalDeadline := helmTemplateDeadline
	helmTemplateDeadline = testwait.Deadline(2 * time.Second)
	t.Cleanup(func() { helmTemplateDeadline = originalDeadline })

	start := time.Now()
	out, err := helmTemplate(t, "stuck", "chart")
	elapsed := time.Since(start)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "helm template stuck chart did not finish") {
		t.Fatalf("helmTemplate err = %v, want named deadline failure", err)
	}
	if !strings.Contains(string(out), "rendering") {
		t.Fatalf("helmTemplate output = %q, want the output helm wrote before it stalled", out)
	}
	if limit := helmTemplateDeadline + testwait.Deadline(helmWaitDelay+10*time.Second); elapsed > limit {
		t.Fatalf("helmTemplate returned after %s, want under %s", elapsed, limit)
	}
}

// A helm that exits while a child it started still holds the output pipe must
// not hold the test until that child finishes: Wait gives up after
// helmWaitDelay and reports exec.ErrWaitDelay with the output read so far.
func TestHelmTemplateStopsWaitingForAnInheritedPipe(t *testing.T) {
	// The background sleep keeps the inherited stdout open after the shell
	// exits 0. It is bounded so the orphan ends on its own after the test.
	useStandInHelm(t, "#!/bin/sh\necho rendering\nsleep 30 &\nexit 0\n")
	originalDelay := helmWaitDelay
	helmWaitDelay = 200 * time.Millisecond
	t.Cleanup(func() { helmWaitDelay = originalDelay })

	start := time.Now()
	out, err := helmTemplate(t, "lingering", "chart")
	elapsed := time.Since(start)
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("helmTemplate err = %v, want exec.ErrWaitDelay", err)
	}
	if !strings.Contains(string(out), "rendering") {
		t.Fatalf("helmTemplate output = %q, want the output helm wrote before it exited", out)
	}
	if limit := testwait.Deadline(10 * time.Second); elapsed > limit {
		t.Fatalf("helmTemplate returned after %s, want under %s", elapsed, limit)
	}
}
