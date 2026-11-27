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

// helmBinary and helmTemplateDeadline are variables so the deadline test can
// substitute a stand-in that never exits.
var (
	helmBinary           = "helm"
	helmTemplateDeadline = testwait.Deadline(2 * time.Minute)
)

// helmWaitDelay bounds how long Wait keeps reading output after the deadline
// kills helm, in case a helm child process still holds the output pipe.
const helmWaitDelay = 5 * time.Second

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

func TestHelmTemplateFailsAtItsDeadline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stand-in helm is a POSIX shell script")
	}
	stub := filepath.Join(t.TempDir(), "helm")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho rendering\nexec sleep 600\n"), 0o700); err != nil { // #nosec G306 -- test stand-in must be executable.
		t.Fatal(err)
	}
	originalBinary, originalDeadline := helmBinary, helmTemplateDeadline
	helmBinary, helmTemplateDeadline = stub, 200*time.Millisecond
	t.Cleanup(func() { helmBinary, helmTemplateDeadline = originalBinary, originalDeadline })

	start := time.Now()
	out, err := helmTemplate(t, "stuck", "chart")
	elapsed := time.Since(start)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "helm template stuck chart did not finish") {
		t.Fatalf("helmTemplate err = %v, want named deadline failure", err)
	}
	if !strings.Contains(string(out), "rendering") {
		t.Fatalf("helmTemplate output = %q, want the output helm wrote before it stalled", out)
	}
	if limit := testwait.Deadline(helmWaitDelay + 10*time.Second); elapsed > limit {
		t.Fatalf("helmTemplate returned after %s, want under %s", elapsed, limit)
	}
}
