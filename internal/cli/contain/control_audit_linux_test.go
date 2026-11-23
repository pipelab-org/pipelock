// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/workspacediff"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func controlAuditFixture(t *testing.T) (controlAuditEnv, string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return controlAuditEnv{
		store: controlAuditStore{
			path: filepath.Join(dir, "contain", "control-audit"),
			uid:  uint32(os.Geteuid()), gid: uint32(os.Getegid()), // #nosec G115 -- Linux returns unsigned 32-bit effective IDs.
		},
		euid: func() int { return 0 }, budget: workspacediff.DefaultControlSurfaceBudget(),
	}, t.TempDir()
}

func runAuditFixture(t *testing.T, env controlAuditEnv, opts controlAuditOptions, want int) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := env.run(&out, opts)
	code := 0
	if err != nil {
		code = cliutil.ExitCodeOf(err)
	}
	if code != want {
		t.Fatalf("exit %d, want %d: %v\n%s", code, want, err, out.String())
	}
	return out.String(), err
}

func writeAuditFixture(t *testing.T, dir, name, contents string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestControlAuditMissingBaseline(t *testing.T) {
	env, root := controlAuditFixture(t)
	out, _ := runAuditFixture(t, env, controlAuditOptions{workspace: root}, 2)
	if !strings.Contains(out, "workspace_control_surface=unavailable reason=missing_baseline") ||
		!strings.Contains(out, recordRemedy(root, false)) || strings.Contains(out, "workspace_control_surface=clean") {
		t.Fatalf("missing baseline result: %s", out)
	}
}

func TestControlAuditRecordReplacement(t *testing.T) {
	env, root := controlAuditFixture(t)
	writeAuditFixture(t, root, ".envrc", "before")
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true}, 0)
	writeAuditFixture(t, root, ".envrc", "after")
	_, err := runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true}, 1)
	if !strings.Contains(err.Error(), recordRemedy(root, true)) {
		t.Fatalf("expected replacement remedy: %v", err)
	}
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root}, 2)
	out, _ := runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true, replace: true}, 0)
	if !strings.Contains(out, "workspace_control_surface=changed") || !strings.Contains(out, ".envrc") {
		t.Fatalf("replacement did not show diff: %s", out)
	}
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root}, 0)
}

func TestControlAuditExitMatrix(t *testing.T) {
	for _, tc := range []struct {
		name       string
		wantStatus string
		changed    bool
		partial    bool
		incomplete bool
	}{
		{name: "clean", wantStatus: "clean"},
		{name: "changed", wantStatus: "changed", changed: true},
		{name: "partial", wantStatus: "partial", partial: true},
		{name: "both", wantStatus: "changed", changed: true, partial: true},
		{name: "incomplete", wantStatus: "incomplete", incomplete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, root := controlAuditFixture(t)
			writeAuditFixture(t, root, ".envrc", "before")
			_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true}, 0)
			if tc.changed {
				writeAuditFixture(t, root, ".envrc", "after")
			}
			if tc.partial {
				env.budget.MaxNestedDepth = 1
				writeAuditFixture(t, root, "ordinary/deep/leaf", "fixture")
			}
			if tc.incomplete {
				if err := os.Rename(root, root+"-previous"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(root + "-previous") })
				if err := os.Mkdir(root, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			for flags := range 4 {
				t.Run(fmt.Sprintf("flags-%d", flags), func(t *testing.T) {
					opts := controlAuditOptions{workspace: root, json: true, allowChanges: flags&1 != 0, allowPartial: flags&2 != 0}
					want := 0
					if tc.incomplete || (tc.changed && !opts.allowChanges) || (tc.partial && !opts.allowPartial) {
						want = 2
					}
					out, _ := runAuditFixture(t, env, opts, want)
					var results []controlAuditResult
					if err := json.Unmarshal([]byte(out), &results); err != nil {
						t.Fatal(err)
					}
					if len(results) != 1 || results[0].Status != tc.wantStatus || (want != 0 && results[0].Remedy == "") {
						t.Fatalf("unexpected JSON audit result: %s", out)
					}
				})
			}
		})
	}
}

func TestControlAuditIncompleteBaselinePersists(t *testing.T) {
	env, root := controlAuditFixture(t)
	writeAuditFixture(t, root, ".claude/settings.json", "fixture")
	writeAuditFixture(t, root, ".claude/policy.json", "fixture")
	env.budget.MaxControlEntries = 1
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true}, 2)
	env.budget = workspacediff.DefaultControlSurfaceBudget()
	out, _ := runAuditFixture(t, env, controlAuditOptions{workspace: root, allowChanges: true, allowPartial: true}, 2)
	if !strings.Contains(out, "workspace_control_surface=incomplete") {
		t.Fatalf("incomplete saved baseline must continue to fail: %s", out)
	}
}

func TestControlAuditAgentIncludesExpiredGrants(t *testing.T) {
	env, root := controlAuditFixture(t)
	expired := t.TempDir()
	const agent = "pipelock-agent"
	inv := workspaceInventory{Workspaces: []workspaceGrant{
		{Path: root, AgentUser: agent},
		{Path: expired, AgentUser: agent, Expires: "2020-01-01T00:00:00Z"},
		{Path: t.TempDir(), AgentUser: "other-agent"},
	}}
	env.readInventory = func(string) ([]byte, error) { return json.Marshal(inv) }
	_, _ = runAuditFixture(t, env, controlAuditOptions{agentUser: agent, record: true}, 0)
	writeAuditFixture(t, expired, ".envrc", "fixture")
	out, _ := runAuditFixture(t, env, controlAuditOptions{agentUser: agent}, 2)
	if !strings.Contains(out, filepath.Join(expired, ".envrc")) ||
		strings.Count(out, "workspace_control_surface=") != 2 {
		t.Fatalf("unexpected agent inventory audit: %s", out)
	}
}

func TestControlAuditRequiresRoot(t *testing.T) {
	env, root := controlAuditFixture(t)
	env.euid = func() int { return 1000 }
	_, err := runAuditFixture(t, env, controlAuditOptions{workspace: root}, 1)
	if !strings.Contains(err.Error(), "requires root") {
		t.Fatal(err)
	}
}

func TestControlAuditStoreRejectsUnsafeDirectory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *controlAuditEnv)
	}{
		{name: "world writable", change: func(t *testing.T, env *controlAuditEnv) {
			if err := os.Chmod(env.store.path, 0o707); err != nil { // #nosec G302 -- unsafe directory fixture.
				t.Fatal(err)
			}
		}},
		{name: "group writable ancestor", change: func(t *testing.T, env *controlAuditEnv) {
			if err := os.Chmod(filepath.Dir(env.store.path), 0o770); err != nil { // #nosec G302 -- unsafe ancestor fixture.
				t.Fatal(err)
			}
		}},
		{name: "symlink", change: func(t *testing.T, env *controlAuditEnv) {
			if err := os.Rename(env.store.path, env.store.path+"-moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(env.store.path+"-moved", env.store.path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "owner", change: func(t *testing.T, env *controlAuditEnv) {
			if os.Geteuid() != 0 {
				t.Skip("changing the on-disk owner requires root")
			}
			if err := os.Chown(env.store.path, 65534, 0); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, root := controlAuditFixture(t)
			_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true}, 0)
			tc.change(t, &env)
			_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root}, 1)
		})
	}
}

func TestControlAuditStoreRejectsInvalidBaseline(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, string, []byte)
	}{
		{name: "unknown field", change: func(t *testing.T, path string, data []byte) {
			writeAuditFixture(t, filepath.Dir(path), filepath.Base(path), string(data[:len(data)-1])+`,"unknown":true}`)
		}},
		{name: "truncated", change: func(t *testing.T, path string, data []byte) {
			writeAuditFixture(t, filepath.Dir(path), filepath.Base(path), string(data[:len(data)/2]))
		}},
		{name: "oversized", change: func(t *testing.T, path string, _ []byte) {
			if err := os.Truncate(path, 129<<20); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink", change: func(t *testing.T, path string, _ []byte) {
			if err := os.Rename(path, path+"-moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+"-moved", path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "mode", change: func(t *testing.T, path string, _ []byte) {
			if err := os.Chmod(path, 0o640); err != nil { // #nosec G302 -- unsafe file fixture.
				t.Fatal(err)
			}
		}},
		{name: "mismatched root", change: func(t *testing.T, path string, _ []byte) {
			other, err := workspacediff.SnapshotControlSurface(t.TempDir(), defaultWorkspaceDiffCapBytes, workspacediff.DefaultControlSurfaceBudget())
			if err != nil {
				t.Fatal(err)
			}
			data, err := workspacediff.EncodeControlBaseline(other)
			if err != nil {
				t.Fatal(err)
			}
			writeAuditFixture(t, filepath.Dir(path), filepath.Base(path), string(data))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, root := controlAuditFixture(t)
			_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true}, 0)
			path := filepath.Join(env.store.path, controlBaselineFilename(root))
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			tc.change(t, path, data)
			_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root}, 1)
		})
	}
}

func TestControlAuditPublishNoReplace(t *testing.T) {
	env, root := controlAuditFixture(t)
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true}, 0)
	dir, err := env.store.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	snap, err := env.store.load(dir, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeControlBaseline(dir, root, snap, false); err == nil {
		t.Fatal("atomic publication overwrote an existing baseline")
	}
}

func TestControlAuditCommandHelpAndUsage(t *testing.T) {
	cmd := auditWorkspaceCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--replace", "--workspace", "/workspace"})
	if err := cmd.Execute(); err == nil || cliutil.ExitCodeOf(err) != 1 {
		t.Fatalf("invalid usage should exit 1: %v", err)
	}
	data, err := os.ReadFile("../../../docs/contain-cli.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd.Long, controlAuditExitCodes) || !bytes.Contains(data, []byte(controlAuditExitCodes)) {
		t.Fatal("exit code table differs between help and documentation")
	}
}

func TestControlAuditStoreRejectsNonRootPrivateOwner(t *testing.T) {
	store := controlAuditStore{}
	stat := unix.Stat_t{Uid: 123, Mode: unix.S_IFDIR | 0o700}
	if err := store.checkDir(stat, true); err == nil {
		t.Fatal("accepted a private directory owned by a non-root user")
	}
	stat.Uid = 0
	if err := store.checkDir(stat, true); err != nil {
		t.Fatalf("rejected correct owner and mode: %v", err)
	}
}

func TestControlAuditStoreHiddenAndRemovedOnlyWhenRequested(t *testing.T) {
	in := filesystemProfileInput{Exists: func(path string) (bool, error) { return path == defaultControlAuditDir, nil }}
	hidden, err := in.inaccessiblePaths()
	if err != nil || !slices.Contains(hidden, defaultControlAuditDir) {
		t.Fatalf("store should be included in InaccessiblePaths: %v, %v", hidden, err)
	}
	env, root := controlAuditFixture(t)
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true}, 0)
	install := &installEnv{controlAuditDir: filepath.Dir(env.store.path)}
	for _, keep := range []bool{true, false} {
		actions := rollbackActions(rollbackOpts{keepData: keep})
		index := slices.IndexFunc(actions, func(action step) bool { return action.name == "remove-dir-control-audit" })
		if index < 0 {
			t.Fatal("rollback does not include control-audit action")
		}
		if err := actions[index].undo(context.Background(), install); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(env.store.path)
		if (keep && err != nil) || (!keep && !errors.Is(err, os.ErrNotExist)) {
			t.Fatalf("keep data %t: store stat error = %v", keep, err)
		}
	}
}

type rejectedAuditOutput struct{}

func (rejectedAuditOutput) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestControlAuditReplaceRequiresVisibleDiff(t *testing.T) {
	env, root := controlAuditFixture(t)
	writeAuditFixture(t, root, ".envrc", "before")
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true}, 0)
	writeAuditFixture(t, root, ".envrc", "after")
	opts := controlAuditOptions{workspace: root, record: true, replace: true}
	if err := env.run(rejectedAuditOutput{}, opts); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("replacing with a failed preview must error: %v", err)
	}
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root}, 2)
}

func TestControlAuditReplaceAfterRebootStillShowsChangedPaths(t *testing.T) {
	env, root := controlAuditFixture(t)
	writeAuditFixture(t, root, ".envrc", "before")
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true}, 0)
	path := filepath.Join(env.store.path, controlBaselineFilename(root))
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Skip("boot ID unavailable")
	}
	current := bytes.TrimSpace(boot)
	if !bytes.Contains(data, current) {
		t.Fatal("baseline does not record the boot ID")
	}
	writeAuditFixture(t, filepath.Dir(path), filepath.Base(path),
		string(bytes.ReplaceAll(data, current, []byte("00000000-0000-0000-0000-000000000000"))))
	writeAuditFixture(t, root, ".envrc", "hostile")
	out, _ := runAuditFixture(t, env, controlAuditOptions{workspace: root}, 2)
	if !strings.Contains(out, "host rebooted") || !strings.Contains(out, ".envrc") {
		t.Fatalf("audit after a reboot must report the incomplete comparison and the changed path: %s", out)
	}
	out, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root, record: true, replace: true}, 0)
	if !strings.Contains(out, "Replacing workspace control baseline") || !strings.Contains(out, ".envrc") {
		t.Fatalf("replacement after a reboot hid the changed path: %s", out)
	}
	_, _ = runAuditFixture(t, env, controlAuditOptions{workspace: root}, 0)
}
