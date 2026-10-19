// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package edition

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	clockHookPkg     = "github.com/luckyPipewrench/pipelock/internal/edition/internal/clockhook"
	licenseClockTest = "github.com/luckyPipewrench/pipelock/internal/edition/licenseclocktest"
	editionPkg       = "github.com/luckyPipewrench/pipelock/internal/edition"
)

// guardedGOOS are the release targets; file-level GOOS constraints can add
// imports on one of them only, so each is listed separately.
var guardedGOOS = []string{"linux", "darwin", "windows"}

func goList(t *testing.T, goos string, args ...string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	gomod, err := exec.CommandContext(t.Context(), goBin, "env", "GOMOD").Output() // #nosec G204 -- go toolchain from PATH; the arguments are literals.
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	// #nosec G204 -- go toolchain from PATH; arguments are test literals, plus,
	// for -deps, a package path read from this module's own go list output.
	cmd := exec.CommandContext(t.Context(), goBin, append([]string{"list"}, args...)...)
	cmd.Env = append(os.Environ(), "GOOS="+goos)
	cmd.Dir = filepath.Dir(strings.TrimSpace(string(gomod)))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}

// Shipped binaries must not link the license clock test support under either
// build tag.
func TestCmdBinariesDoNotLinkLicenseClockOverrides(t *testing.T) {
	for _, goos := range guardedGOOS {
		for _, tags := range []string{"", "enterprise"} {
			t.Run(goos+"/tags="+tags, func(t *testing.T) {
				cmds := strings.Fields(goList(t, goos, "-tags", tags, "./cmd/..."))
				if len(cmds) == 0 {
					t.Fatal("no command packages found")
				}
				for _, dep := range strings.Fields(goList(t, goos, "-tags", tags, "-deps", "./cmd/...")) {
					if dep == licenseClockTest {
						t.Errorf("GOOS=%s tags=%q: cmd binaries link %s", goos, tags, dep)
					}
				}
			})
		}
	}
}

// Only package edition (which fills the hook) and licenseclocktest may import
// the clock hook, in code or tests.
func TestOnlyLicenseClockTestReachesClockHook(t *testing.T) {
	allowed := map[string]bool{editionPkg: true, licenseClockTest: true}
	for _, goos := range guardedGOOS {
		for _, tags := range []string{"", "enterprise"} {
			out := goList(t, goos, "-tags", tags, "-f", "{{.ImportPath}} {{join .Imports \" \"}} {{join .TestImports \" \"}} {{join .XTestImports \" \"}}", "./...")
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				for _, imp := range fields[1:] {
					if imp == clockHookPkg && !allowed[fields[0]] {
						t.Errorf("GOOS=%s tags=%q: %s imports the license clock hook", goos, tags, fields[0])
					}
				}
			}
		}
	}
}
