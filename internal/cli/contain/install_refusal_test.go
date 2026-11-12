// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestInstallNFTPreflightValidatesExecutableBeforeRun(t *testing.T) {
	for _, tc := range []struct {
		name, path, want string
		mode             os.FileMode
		uid              uint32
		statErr          error
	}{
		{"relative", "nft", "absolute path", 0o700, 0, nil},
		{"missing", "/missing/nft", "not found", 0o700, 0, os.ErrNotExist},
		{"not executable", "/untrusted/nft", "not executable", 0o600, 0, nil},
		{"group writable", "/untrusted/nft", "must not be group- or world-writable", 0o720, 0, nil},
		{"foreign owner", "/untrusted/nft", "root-owned", 0o700, 1000, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			env.nftPath = tc.path
			stat := env.stat
			env.stat = func(path string) (os.FileInfo, error) {
				if path == tc.path {
					return fakeFileInfo{mode: tc.mode, sys: fakeFileSysWithUID(tc.uid)}, tc.statErr
				}
				return stat(path)
			}
			err := preflightInstallNFTRules(t.Context(), env, managedPipelockConfigPath(env))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %s", err, tc.want)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("untrusted nft executed: %+v", runner.calls)
			}
		})
	}
}

func TestInstallNFTPreflightValidatesConfigBeforeIdentityDeferral(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		t.Run(map[bool]string{true: "dry", false: "real"}[dryRun], func(t *testing.T) {
			env, _, out := newFakeEnv(t)
			trustInstallNFTForTest(env)
			lookup := env.lookupUser
			env.lookupUser = func(name string) (*user.User, error) {
				if name == env.agentUserName {
					return nil, user.UnknownUserError(name)
				}
				return lookup(name)
			}
			src := filepath.Join(t.TempDir(), "candidate.yaml")
			if err := os.WriteFile(src, []byte("mode: balanced\nforward_proxy:\n  enabled: true\ncontainment:\n  agent_listener: 10.1.2.3:9000\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := runInstall(t.Context(), env, installOpts{dryRun: dryRun, configSource: src})
			if err == nil || !strings.Contains(err.Error(), "managed listener config "+src) || strings.Contains(out.String(), "[DEFERRED]") {
				t.Fatalf("error=%v, output=%s", err, out)
			}
		})
	}
}

func TestInstallNFTRefusalRevokesOnlyStaleDoorways(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		t.Run(map[bool]string{true: "dry", false: "real"}[dryRun], func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			trustInstallNFTForTest(env)
			keep := loopbackTestService(9201)
			stale := loopbackTestService(9200)
			inventory := desiredLoopbackForwarders([]config.ContainmentLoopbackService{stale, keep})
			data, err := json.Marshal(inventory)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(env.loopbackForwarderInvPath), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(env.loopbackForwarderInvPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			publication := publishedTestService()
			records, err := encodePublishedServiceRecords(desiredPublishedServices([]config.ContainmentPublishedService{publication}))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(publishedServiceRecordPath(env.loopbackForwarderInvPath), records, 0o600); err != nil {
				t.Fatal(err)
			}
			body := "mode: balanced\nforward_proxy:\n  enabled: true\n" + loopbackConfigYAML(loopbackEntryYAML(keep.Host, keep.Port, keep.ExpiresAt))
			if err := os.WriteFile(managedPipelockConfigPath(env), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join(t.TempDir(), "candidate.yaml")
			if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			policy := reconcileTestPolicy()
			live := wrapNFTListingForTest("meta skuid 987 accept # handle 10\n" + nftListingFromRulesBodyForTest(policy.rules, 20))
			runner.on(argvFor(env.nftPath, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), live, 0, nil)
			locked, locks := false, 0
			env.reconcileLockPath = containmentReconcileLockPathFor(env.nftRulesPath)
			env.lockFn = func(_ string, fn func() error) error {
				locks++
				locked = true
				defer func() { locked = false }()
				return fn()
			}
			run := env.runCmd
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if filepath.Base(name) == "systemctl" {
					if !locked {
						t.Fatal("doorway cleanup ran outside lock")
					}
					if args[0] != "stop" && args[0] != "disable" && args[0] != "show" {
						t.Fatalf("cleanup opened grant: %s %v", name, args)
					}
					if strings.Contains(strings.Join(args, " "), loopbackForwarderUnitBase(keep.Host, keep.Port)) {
						t.Fatalf("valid grant touched: %v", args)
					}
					if args[0] == "show" {
						return "inactive\n", 0, nil
					}
					name = "systemctl"
				}
				return run(ctx, name, args...)
			}
			look := env.lookPath
			env.lookPath = func(name string) (string, error) {
				if name == "systemctl" {
					return "/usr/bin/systemctl", nil
				}
				return look(name)
			}
			stat := env.stat
			env.stat = func(path string) (os.FileInfo, error) {
				if path == "/usr/bin/systemctl" {
					return fakeFileInfo{mode: 0o700, sys: fakeFileSysWithUID(0)}, nil
				}
				return stat(path)
			}
			err = runInstall(t.Context(), env, installOpts{dryRun: dryRun, configSource: src})
			if err == nil || !strings.Contains(err.Error(), "nft reconciliation conflict") {
				t.Fatalf("error=%v", err)
			}
			stopped := runnerCalled(runner, "stop "+loopbackForwarderUnitBase(stale.Host, stale.Port)+".service")
			publishedStopped := runnerCalled(runner, "stop pipelock-published-viewer.service")
			if stopped != !dryRun || publishedStopped != !dryRun || (locks > 0) != !dryRun {
				t.Fatalf("stopped=%v published=%v locks=%d dry=%v", stopped, publishedStopped, locks, dryRun)
			}
			if dryRun && len(runner.calls) != 1 {
				t.Fatalf("dry-run commands: %+v", runner.calls)
			}
		})
	}
}

// Keep general step-level fixtures independent of executable resolution.
// Early preflight tests use the production absolute-path contract instead.
func trustInstallNFTForTest(env *installEnv) {
	env.nftPath = "/usr/sbin/nft"
	stat := env.stat
	env.stat = func(path string) (os.FileInfo, error) {
		if path == "/usr/sbin/nft" {
			return fakeFileInfo{mode: 0o700, sys: fakeFileSysWithUID(0)}, nil
		}
		return stat(path)
	}
}

func TestInstallRefusalDoorwayPolicyIntersection(t *testing.T) {
	for _, tc := range []struct {
		name, installed, candidate  string
		wantLoopback, wantPublished bool
	}{
		{"unchanged active grants", "active", "active", false, false},
		{"removed candidate grants", "active", "empty", true, true},
		{"expired installed grants", "expired", "active", true, true},
		{"expired candidate grants", "active", "expired", true, true},
		{"missing installed config", "missing", "active", true, true},
		{"broken installed config", "broken", "active", true, true},
		{"unreadable candidate", "active", "unreadable", true, true},
		{"candidate replaces operator", "active", "operator", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			service := loopbackTestService(9200)
			putInstallRefusalInventories(t, env, []config.ContainmentLoopbackService{service})
			active := loopbackConfigYAML(loopbackEntryYAML(service.Host, service.Port, service.ExpiresAt)) + strings.TrimPrefix(publishedTestConfig, "containment:\n")
			expired := strings.ReplaceAll(strings.ReplaceAll(active, service.ExpiresAt, expiredLoopbackTestStamp), futureExpiryForTest, expiredLoopbackTestStamp)
			candidatePath := filepath.Join(t.TempDir(), "candidate.yaml")
			read := env.readFile
			for _, item := range []struct{ path, kind string }{{managedPipelockConfigPath(env), tc.installed}, {candidatePath, tc.candidate}} {
				body := active
				switch item.kind {
				case "missing":
					continue
				case "empty":
					body = "mode: balanced\n"
				case "expired":
					body = expired
				case "broken":
					body = "containment: ["
				case "operator":
					body = strings.Replace(active, "operator_user: operator\n", "operator_user: other\n", 1)
				case "unreadable":
					path := item.path
					env.readFile = func(p string) ([]byte, error) {
						if p == path {
							return nil, os.ErrPermission
						}
						return read(p)
					}
					continue
				}
				if err := os.WriteFile(item.path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			loopback, publication, err := installRefusalDoorwayPlan(env, candidatePath)
			if (len(loopback) > 0) != tc.wantLoopback || (len(publication) > 0) != tc.wantPublished {
				t.Fatalf("loopback=%v publication=%v error=%v", loopback, publication, err)
			}
			wantError := tc.installed == "broken" || tc.candidate == "unreadable"
			if (err != nil) != wantError {
				t.Fatalf("error=%v, want error=%v", err, wantError)
			}
		})
	}
}

func putInstallRefusalInventories(t *testing.T, env *installEnv, services []config.ContainmentLoopbackService) {
	t.Helper()
	data, err := json.Marshal(desiredLoopbackForwarders(services))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(env.loopbackForwarderInvPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.loopbackForwarderInvPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err = encodePublishedServiceRecords(desiredPublishedServices([]config.ContainmentPublishedService{publishedTestService()}))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publishedServiceRecordPath(env.loopbackForwarderInvPath), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInstallRefusalReobservesAfterLock(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	service := loopbackTestService(9200)
	putInstallRefusalInventories(t, env, []config.ContainmentLoopbackService{service})
	src := managedPipelockConfigPath(env)
	if err := os.WriteFile(src, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.reconcileLockPath = containmentReconcileLockPathFor(env.nftRulesPath)
	called := false
	env.lockFn = func(_ string, fn func() error) error {
		called = true
		body := loopbackConfigYAML(loopbackEntryYAML(service.Host, service.Port, service.ExpiresAt)) + strings.TrimPrefix(publishedTestConfig, "containment:\n")
		if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
			return err
		}
		return fn()
	}
	if err := revokeInstallRefusalDoorways(t.Context(), env, src); err != nil {
		t.Fatal(err)
	}
	if !called || len(runner.calls) != 0 {
		t.Fatalf("lock=%v commands=%+v", called, runner.calls)
	}
}

func TestInstallRefusalCleanupFailures(t *testing.T) {
	for _, stage := range []string{"lookup", "relative", "untrusted", "lock", "stop", "observe"} {
		t.Run(stage, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			putInstallRefusalInventories(t, env, []config.ContainmentLoopbackService{loopbackTestService(9200)})
			src := managedPipelockConfigPath(env)
			if err := os.WriteFile(src, []byte("mode: balanced\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			failure := errors.New("injected cleanup failure")
			env.reconcileLockPath = containmentReconcileLockPathFor(env.nftRulesPath)
			env.lockFn = func(_ string, fn func() error) error {
				if stage == "lock" {
					return failure
				}
				return fn()
			}
			env.lookPath = func(string) (string, error) {
				if stage == "lookup" {
					return "", failure
				}
				if stage == "relative" {
					return "systemctl", nil
				}
				return "/usr/bin/systemctl", nil
			}
			stat := env.stat
			env.stat = func(path string) (os.FileInfo, error) {
				if path == "/usr/bin/systemctl" {
					uid := uint32(0)
					if stage == "untrusted" {
						uid = 1000
					}
					return fakeFileInfo{mode: 0o700, sys: fakeFileSysWithUID(uid)}, nil
				}
				return stat(path)
			}
			run := env.runCmd
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if name != "/usr/bin/systemctl" {
					t.Fatalf("unexpected executable %s", name)
				}
				if stage == "stop" && args[0] == "stop" {
					_, _, _ = run(ctx, "systemctl", args...)
					return "", 1, failure
				}
				if stage == "observe" && args[0] == "show" {
					return "active\n", 0, nil
				}
				return run(ctx, "systemctl", args...)
			}
			err := revokeInstallRefusalDoorways(t.Context(), env, src)
			if err == nil {
				t.Fatal("cleanup failure hidden")
			}
			if stage == "lookup" || stage == "lock" || stage == "stop" {
				if !errors.Is(err, failure) {
					t.Fatalf("lost failure: %v", err)
				}
			}
			if stage == "lookup" || stage == "relative" || stage == "untrusted" || stage == "lock" {
				if len(runner.calls) != 0 {
					t.Fatalf("untrusted cleanup command ran: %+v", runner.calls)
				}
			} else if !runnerCalled(runner, "disable --now pipelock-published-viewer.socket") {
				t.Fatal("loopback failure skipped publication cleanup")
			}
		})
	}
}

func TestInstallRefusalCleanHostDoesNotCreateLock(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.reconcileLockPath = containmentReconcileLockPathFor(env.nftRulesPath)
	env.mkdirAll = func(string, os.FileMode) error { t.Fatal("clean refusal created a directory"); return nil }
	env.lockFn = func(string, func() error) error { t.Fatal("clean refusal created a lock"); return nil }
	// A foreign file with a managed-looking name does not confer ownership.
	foreign := filepath.Join(filepath.Dir(env.proxyForwarderSocketPath), "pipelock-agent-loopback-v4-9200.socket")
	if err := os.WriteFile(foreign, []byte("[Socket]\nListenStream=9200\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := revokeInstallRefusalDoorways(t.Context(), env, managedPipelockConfigPath(env)); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("clean refusal ran commands: %+v", runner.calls)
	}
}

func TestInstallRefusalCanceledCallerAndInventoryError(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	service := loopbackTestService(9200)
	putInstallRefusalInventories(t, env, []config.ContainmentLoopbackService{service})
	// Corrupt publication inventory must not keep an independently observed
	// owned unit open, and must not hide the inventory failure.
	if err := os.WriteFile(publishedServiceRecordPath(env.loopbackForwarderInvPath), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, file := range publishedServiceFiles(filepath.Dir(env.proxyForwarderSocketPath), env.pipelockTarget, env.proxyUserName, publishedTestService()) {
		if err := os.WriteFile(file.path, []byte(file.body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env.lookPath = func(string) (string, error) { return "/usr/bin/systemctl", nil }
	stat := env.stat
	env.stat = func(path string) (os.FileInfo, error) {
		if path == "/usr/bin/systemctl" {
			return fakeFileInfo{mode: 0o700, sys: fakeFileSysWithUID(0)}, nil
		}
		return stat(path)
	}
	run := env.runCmd
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if ctx.Err() != nil {
			t.Fatalf("revocation inherited cancellation: %v", ctx.Err())
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("revocation command has no deadline")
		}
		if name != "/usr/bin/systemctl" {
			t.Fatalf("cleanup executable=%s", name)
		}
		return run(ctx, "systemctl", args...)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := revokeInstallRefusalDoorways(ctx, env, managedPipelockConfigPath(env))
	if err == nil || !strings.Contains(err.Error(), "published") {
		t.Fatalf("inventory failure hidden: %v", err)
	}
	if !runnerCalled(runner, "stop "+loopbackForwarderUnitBase(service.Host, service.Port)+".service") || !runnerCalled(runner, "stop pipelock-published-viewer.service") {
		t.Fatalf("revocation skipped after inventory error: %+v", runner.calls)
	}
}
