// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !mcp_hardening_test

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestBuildRules_ReferABI(t *testing.T) {
	policy := Policy{
		AllowReadDirs:  []string{"/usr"},
		AllowReadFiles: []string{"/etc/hosts"},
		AllowRWDirs:    []string{"/workspace", "/writable"},
		AllowRWFiles:   []string{"/dev/null"},
	}
	for _, abi := range []int{1, 2, 9} {
		t.Run(fmt.Sprintf("ABI%d", abi), func(t *testing.T) {
			writable := landlock.RWDirs(policy.AllowRWDirs...).IgnoreIfMissing()
			if abi >= 2 {
				writable = writable.WithRefer()
			}
			want := []landlock.Rule{
				landlock.RODirs(policy.AllowReadDirs...).IgnoreIfMissing(),
				landlock.ROFiles(policy.AllowReadFiles...).IgnoreIfMissing(),
				writable,
				landlock.RWFiles(policy.AllowRWFiles...).IgnoreIfMissing(),
			}
			if got := buildRules(policy, abi); !reflect.DeepEqual(got, want) {
				t.Fatalf("ABI %d rules = %v, want %v", abi, got, want)
			}
		})
	}
	if landlock.V9.HandledAccessFS&landlock.AccessFSSet(llsys.AccessFSRefer) == 0 {
		t.Fatal("sandbox ruleset must handle REFER before granting it")
	}
}

type reparentingCase struct {
	name   string
	source string
	target string
	link   bool
	allow  bool
}

func reparentingCases() []reparentingCase {
	return []reparentingCase{
		{name: "same-directory rename", source: "workspace/source", target: "workspace/target", allow: true},
		{name: "same-directory hard link", source: "workspace/source", target: "workspace/target", link: true, allow: true},
		{name: "workspace cross-directory rename", source: "workspace/source", target: "workspace/d/target", allow: true},
		{name: "workspace directory rename", source: "workspace/d", target: "workspace/other/d", allow: true},
		{name: "workspace hard link", source: "workspace/source", target: "workspace/d/target", link: true, allow: true},
		{name: "writable grant rename", source: "workspace/source", target: "writable/target", allow: true},
		{name: "writable grant rename into workspace", source: "writable/source", target: "workspace/d/target", allow: true},
		{name: "writable grant hard link", source: "writable/source", target: "workspace/d/target", link: true, allow: true},
		{name: "rename outside", source: "workspace/source", target: "outside/target"},
		{name: "hard link outside", source: "workspace/source", target: "outside/target", link: true},
		{name: "hard link to read-only grant", source: "workspace/source", target: "readonly/target", link: true},
		{name: "rename to read-only grant", source: "workspace/source", target: "readonly/target"},
		{name: "rename from read-only grant", source: "readonly/source", target: "workspace/target"},
		{name: "hard link from read-only grant", source: "readonly/source", target: "workspace/target", link: true},
		{name: "rename from writable file grant", source: "files/source", target: "workspace/target"},
		{name: "hard link from writable file grant", source: "files/source", target: "workspace/target", link: true},
	}
}

func reparentingFixture(t *testing.T) (string, Policy) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"workspace/d", "workspace/other", "writable", "readonly", "outside", "files"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"workspace", "writable", "readonly", "files"} {
		if err := os.WriteFile(filepath.Join(root, dir, "source"), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	policy := DefaultPolicy(filepath.Join(root, "workspace"))
	policy.AllowRWDirs = append(policy.AllowRWDirs, filepath.Join(root, "writable"))
	policy.AllowReadDirs = append(policy.AllowReadDirs, filepath.Join(root, "readonly"))
	policy.AllowRWFiles = append(policy.AllowRWFiles, filepath.Join(root, "files/source"))
	return root, policy
}

func TestLandlock_Reparenting(t *testing.T) {
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil || abi < 1 {
		t.Skipf("Landlock unavailable: ABI=%d err=%v", abi, err)
	}
	for _, abi1 := range []bool{false, true} {
		name := "native"
		if abi1 {
			name = "ABI1"
		}
		t.Run(name, func(t *testing.T) {
			if !abi1 && abi < 2 {
				t.Skipf("cross-directory operations require Landlock ABI 2 (kernel ABI %d)", abi)
			}
			for _, tc := range reparentingCases() {
				t.Run(tc.name, func(t *testing.T) {
					root, policy := reparentingFixture(t)
					t.Setenv("PIPELOCK_TEST_REFER_ROOT", root)
					t.Setenv("PIPELOCK_TEST_REFER_SOURCE", tc.source)
					t.Setenv("PIPELOCK_TEST_REFER_TARGET", tc.target)
					t.Setenv("PIPELOCK_TEST_REFER_LINK", strconv.FormatBool(tc.link))
					t.Setenv("PIPELOCK_TEST_REFER_ABI1", strconv.FormatBool(abi1))
					out, code := runSandboxedChild(t, "reparent", policy.Workspace)
					if code != 0 {
						t.Fatalf("Landlock child exit %d: %s", code, out)
					}
					allow := tc.allow && (!abi1 || filepath.Dir(tc.source) == filepath.Dir(tc.target))
					assertReparenting(t, root, tc, allow, out)
				})
			}
		})
	}
}

func assertReparenting(t *testing.T, root string, tc reparentingCase, allow bool, out string) {
	t.Helper()
	want := "denied\n"
	if allow {
		want = "allowed\n"
	}
	if !strings.Contains(out, want) {
		t.Fatalf("expected %q, got %q", want, out)
	}
	_, err := os.Stat(filepath.Join(root, tc.target))
	if allow && err != nil {
		t.Fatalf("allowed destination missing: %v", err)
	}
	if !allow {
		if !os.IsNotExist(err) {
			t.Fatalf("denied destination should be absent: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, tc.source)); err != nil {
			t.Fatalf("denied operation changed source: %v", err)
		}
	}
	if allow && !tc.link {
		if _, err := os.Stat(filepath.Join(root, tc.source)); !os.IsNotExist(err) {
			t.Fatalf("rename source should be absent: %v", err)
		}
	}
	if allow && tc.link {
		source, err := os.Stat(filepath.Join(root, tc.source))
		if err != nil {
			t.Fatal(err)
		}
		target, err := os.Stat(filepath.Join(root, tc.target))
		if err != nil || !os.SameFile(source, target) {
			t.Fatalf("hard link must refer to the same inode: %v", err)
		}
	}
}

const reparentingProbe = `
import errno, os, sys
try:
    (os.link if sys.argv[3] == "true" else os.rename)(sys.argv[1], sys.argv[2])
    print("allowed")
except OSError as e:
    if e.errno not in (errno.EXDEV, errno.EACCES):
        raise
    print("denied")
`

func TestLaunchSandboxed_Reparenting(t *testing.T) {
	requireStrictSandboxPrimitives(t)
	if abi := Detect().LandlockABI; abi < 2 {
		t.Skipf("cross-directory operations require Landlock ABI 2 (kernel ABI %d)", abi)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable for sandbox file operation probe")
	}
	for _, tc := range reparentingCases() {
		t.Run(tc.name, func(t *testing.T) {
			root, policy := reparentingFixture(t)
			stdout, stderr := &lockedBuffer{}, &lockedBuffer{}
			err := launchSandboxedToCompletion(t, LaunchConfig{
				Command: []string{
					python, "-c", reparentingProbe,
					filepath.Join(root, tc.source), filepath.Join(root, tc.target), strconv.FormatBool(tc.link),
				},
				Workspace: policy.Workspace,
				Policy:    &policy,
				Strict:    true,
				Stdout:    stdout,
				Stderr:    stderr,
			})
			if err != nil {
				t.Fatalf("sandbox: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
			}
			assertReparenting(t, root, tc, tc.allow, stdout.String())
		})
	}
}
