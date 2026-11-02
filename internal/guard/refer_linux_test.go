// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/landlockcompat"
)

// Real kernel checks run in disposable processes because Landlock is permanent.
func TestApplyForExec_ReferKernel(t *testing.T) {
	if mode := os.Getenv("PIPELOCK_GUARD_REFER_MODE"); mode != "" {
		root := os.Getenv("PIPELOCK_GUARD_REFER_ROOT")
		cfg := planConfig([]config.GuardManifest{{Name: "m", ReadWriteDirectories: []string{root}}}, []string{"m"})
		p, err := Prepare(cfg, "agent", os.Getuid())
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		ops := kernelRulesetOperations()
		ops.getErrata = func() (int, error) {
			if mode == "query-fails" {
				return 0x4, errors.New("query unsupported")
			}
			if mode == "fixed" {
				return 0x4, nil
			}
			return 0, nil
		}
		record, err := p.applyWithOperations(ops, false)
		if err != nil || !record.Enforced() {
			fmt.Printf("apply: %+v %v\n", record, err)
			os.Exit(1)
		}
		var wantWithheld []string
		if mode != "fixed" {
			wantWithheld = []string{ReferWithheldReason}
		}
		if !slices.Equal(record.Withheld, wantWithheld) {
			fmt.Printf("withheld: %v\n", record.Withheld)
			os.Exit(1)
		}
		for _, link := range []bool{false, true} {
			for _, cross := range []bool{false, true} {
				source := filepath.Join(root, fmt.Sprintf("source-%v-%v", link, cross))
				target := filepath.Join(root, fmt.Sprintf("target-%v-%v", link, cross))
				if cross {
					target = filepath.Join(root, "other", filepath.Base(target))
				}
				if link {
					err = os.Link(source, target)
				} else {
					err = os.Rename(source, target)
				}
				if cross && mode != "fixed" {
					if !errors.Is(err, unix.EXDEV) {
						fmt.Printf("cross link=%v: %v, want EXDEV\n", link, err)
						os.Exit(1)
					}
				} else if err != nil {
					fmt.Printf("link=%v cross=%v: %v\n", link, cross, err)
					os.Exit(1)
				}
			}
		}
		fmt.Printf("mode=%s: enforced; same-directory allowed; cross-directory %s\n", mode, map[bool]string{true: "allowed", false: "EXDEV"}[mode == "fixed"])
		os.Exit(0)
	}
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil || abi < MinimumABI {
		t.Skipf("Landlock ABI %d: %v", abi, err)
	}
	for _, mode := range []string{"fixed", "missing", "query-fails"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "fixed" && !landlockcompat.ReferAllowed(abi, llsys.LandlockGetErrata) {
				t.Skip("kernel does not report erratum 3 fixed")
			}
			root := filepath.Join(t.TempDir(), "workspace")
			if err := os.Mkdir(root, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(root, "other"), 0o750); err != nil {
				t.Fatal(err)
			}
			for _, link := range []bool{false, true} {
				for _, cross := range []bool{false, true} {
					if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("source-%v-%v", link, cross)), []byte("fixture"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestApplyForExec_ReferKernel$") // #nosec G204 -- re-exec of this test binary with a fixed run filter.
			cmd.Env = append(os.Environ(), "PIPELOCK_GUARD_REFER_MODE="+mode, "PIPELOCK_GUARD_REFER_ROOT="+root)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child: %v\n%s", err, out)
			}
			t.Logf("%s", out)
		})
	}
}

// ReferErratumMissing reads the running kernel. Compare it with an answer
// derived directly from the two kernel queries.
func TestReferErratumMissingMatchesKernel(t *testing.T) {
	want := false
	if abi, err := llsys.LandlockGetABIVersion(); err == nil {
		errata, errataErr := llsys.LandlockGetErrata()
		want = abi < 2 || errataErr != nil || errata&(1<<(3-1)) == 0
	}
	if got := ReferErratumMissing(); got != want {
		t.Fatalf("ReferErratumMissing() = %v, want %v", got, want)
	}
}
