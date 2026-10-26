// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const testForwarderReady = "ActiveState=active\nSubState=running\nType=notify\nNRestarts=0\n"

func TestNamespaceForwardersRequireReadiness(t *testing.T) {
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9201}
	for name, body := range map[string]string{
		"proxy":    renderContainedNamespaceForwarderUnit("/usr/local/bin/pipelock", testAgentUser, defaultProxyPort),
		"declared": renderDeclaredLoopbackNamespaceForwarderUnit("/usr/local/bin/pipelock", testAgentUser, service),
	} {
		t.Run(name, func(t *testing.T) {
			for _, want := range []string{"Type=notify\n", "NotifyAccess=main\n", fmt.Sprintf("TimeoutStartSec=%d\n", int64(cliutil.ServiceStartTimeout/time.Second)), "BindReadOnlyPaths=/run/systemd/notify\n"} {
				if !strings.Contains(body, want) {
					t.Errorf("unit missing %q", want)
				}
			}
		})
	}
}

// Model systemd.service(5): simple starts complete before the executable binds;
// notify starts fail if it exits before READY=1. No real systemd is invoked.
func TestInstallDeclaredForwarderReadinessFailureRollsBack(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9201}
	services := []config.ContainmentLoopbackService{service}
	unit := loopbackForwarderUnitBase(service.Host, service.Port) + "-netns.service"
	path := filepath.Join(filepath.Dir(env.proxyForwarderSocketPath), unit)
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if name == "systemctl" && strings.Join(args, " ") == "enable --now "+unit {
			body, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				return "", 1, err
			}
			if strings.Contains(string(body), "Type=notify\n") {
				return "start job failed: listener exited before READY=1", 1, nil
			}
		}
		return runner.run(ctx, name, args...)
	}
	_, err := runSteps(t.Context(), env, out, []step{stepInstallNetworkNamespaceWithServices(&services)})
	if err == nil {
		t.Fatal("install accepted a declared listener that never bound")
	}
	for _, want := range []string{"127.0.0.1:9201", "collision"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v; missing %q", err, want)
		}
	}
	for _, p := range []string{path, env.namespaceForwarderServicePath, env.networkNamespaceUnitPath, env.loopbackForwarderInvPath} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("rollback left %s: %v", p, err)
		}
	}
	if !strings.Contains(out.String(), "undo install-agent-network-namespace") {
		t.Fatalf("missing rollback: %s", out)
	}
}

func TestDeclaredForwarderRuntimeReadiness(t *testing.T) {
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9201}
	unit := loopbackForwarderUnitBase(service.Host, service.Port) + "-netns.service"
	for _, tc := range []struct{ name, active, sub, kind, restarts, want string }{
		{"ready", "active", "running", "notify", "0", statusPass},
		{"recovered", "active", "running", "notify", "2", statusPass},
		{"auto restart", "activating", "auto-restart", "notify", "2", statusFail},
		{"auto restart before counter", "activating", "auto-restart", "notify", "0", statusFail},
		{"repeated activation", "activating", "start", "notify", "2", statusFail},
		{"active but exited", "active", "exited", "notify", "0", statusFail},
		{"old loaded type", "active", "running", "simple", "0", statusFail},
		{"missing properties", "active", "", "", "", statusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := diagnosticDoorwayEnv(nil)
			oldRead, oldRun := env.readFile, env.runCmd
			env.readFile = func(path string) ([]byte, error) {
				switch filepath.Base(path) {
				case strings.TrimSuffix(unit, "-netns.service") + ".socket":
					return []byte(renderDeclaredLoopbackSocketUnit(env.agentUserName, service)), nil
				case strings.TrimSuffix(unit, "-netns.service") + ".service":
					return []byte(renderDeclaredLoopbackForwarderUnit(env.pipelockTarget, env.proxyUserName, service)), nil
				case unit:
					return []byte(renderDeclaredLoopbackNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, service)), nil
				}
				return oldRead(path)
			}
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if name == "systemctl" && len(args) > 1 && args[1] == unit {
					switch args[0] {
					case "is-enabled":
						return systemctlEnabled, 0, nil
					case "is-active":
						return tc.active, 0, nil
					case "show":
						return fmt.Sprintf("ActiveState=%s\nSubState=%s\nType=%s\nNRestarts=%s\n", tc.active, tc.sub, tc.kind, tc.restarts), 0, nil
					}
				}
				if name == "systemctl" && len(args) > 1 && args[0] == "show" {
					return testForwarderReady, 0, nil
				}
				return oldRun(ctx, name, args...)
			}
			got := doctorDoorwayState(t.Context(), env, []config.ContainmentLoopbackService{service})
			if got.status != tc.want {
				t.Fatalf("got %+v; want %s", got, tc.want)
			}
			status, _ := probeManagedDoorwaySockets(t.Context(), env, []config.ContainmentLoopbackService{service})
			if (status == statusPass) != (tc.want == statusPass) {
				t.Fatalf("verify status=%s doctor=%+v", status, got)
			}
		})
	}
}

func TestReinstallMigratesSimpleNamespaceForwarders(t *testing.T) {
	for _, failStart := range []bool{false, true} {
		t.Run(fmt.Sprintf("startFails=%t", failStart), func(t *testing.T) {
			env, runner, out := newFakeEnv(t)
			services := []config.ContainmentLoopbackService{{Host: "127.0.0.1", Port: 9201}}
			unit := loopbackForwarderUnitBase(services[0].Host, services[0].Port) + "-netns.service"
			path := filepath.Join(filepath.Dir(env.proxyForwarderSocketPath), unit)
			bodies := map[string]string{
				path:                              renderDeclaredLoopbackNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, services[0]),
				env.namespaceForwarderServicePath: renderContainedNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, env.proxyPort),
			}
			for path, body := range bodies {
				old := strings.ReplaceAll(body, "Type=notify\nNotifyAccess=main\n", "Type=simple\n")
				old = strings.ReplaceAll(old, "BindReadOnlyPaths=/run/systemd/notify\n", "")
				old = strings.ReplaceAll(old, fmt.Sprintf("TimeoutStartSec=%d\n", int64(cliutil.ServiceStartTimeout/time.Second)), "")
				bodies[path] = old
				if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
					t.Fatal(err)
				}
				runner.on(argvFor("systemctl", "is-active", filepath.Base(path)), "active", 0, nil)
				runner.on(argvFor("systemctl", "is-enabled", filepath.Base(path)), "enabled", 0, nil)
			}
			if failStart {
				runner.on(argvFor("systemctl", "restart", unit), "listener exited before READY=1", 1, nil)
			}
			_, err := runSteps(t.Context(), env, out, []step{stepInstallNetworkNamespaceWithServices(&services)})
			if failStart {
				if err == nil || !strings.Contains(err.Error(), "127.0.0.1:9201") {
					t.Fatalf("restart failure=%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			for path, old := range bodies {
				body, readErr := os.ReadFile(filepath.Clean(path))
				if readErr != nil {
					t.Fatal(readErr)
				}
				if failStart {
					if string(body) != old {
						t.Fatalf("rollback did not restore %s", path)
					}
					if !fakeRunnerCalled(runner, "systemctl start "+filepath.Base(path)) {
						t.Fatalf("rollback did not restore runtime state: %s", path)
					}
				} else {
					if !strings.Contains(string(body), "Type=notify\n") {
						t.Fatalf("unit not migrated: %s: %s", path, body)
					}
					if !fakeRunnerCalled(runner, "systemctl restart "+filepath.Base(path)) {
						t.Fatalf("migrated unit not restarted: %s", path)
					}
				}
			}
		})
	}
}

func TestLegacyNamespaceForwarderReadinessRemedy(t *testing.T) {
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9201}
	unit := loopbackForwarderUnitBase(service.Host, service.Port) + "-netns.service"
	for _, declared := range []bool{false, true} {
		t.Run(fmt.Sprintf("declared=%t", declared), func(t *testing.T) {
			env := diagnosticDoorwayEnv(nil)
			oldRead := env.readFile
			target, remedy := containedNamespaceForwarderUnit, installRemedy
			var services []config.ContainmentLoopbackService
			if declared {
				target = unit
				remedy = loopbackDefinitionRemedy
				services = []config.ContainmentLoopbackService{service}
			}
			env.readFile = func(path string) ([]byte, error) {
				var body []byte
				var err error
				if filepath.Base(path) == unit {
					body = []byte(renderDeclaredLoopbackNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, service))
				} else {
					body, err = oldRead(path)
				}
				if filepath.Base(path) == target {
					legacy := strings.ReplaceAll(string(body), "Type=notify\nNotifyAccess=main\n", "Type=simple\n")
					legacy = strings.ReplaceAll(legacy, "BindReadOnlyPaths=/run/systemd/notify\n", "")
					return []byte(legacy), nil
				}
				// Supply healthy definitions for the declared service's siblings.
				if declared {
					switch filepath.Base(path) {
					case strings.TrimSuffix(unit, "-netns.service") + ".socket":
						return []byte(renderDeclaredLoopbackSocketUnit(env.agentUserName, service)), nil
					case strings.TrimSuffix(unit, "-netns.service") + ".service":
						return []byte(renderDeclaredLoopbackForwarderUnit(env.pipelockTarget, env.proxyUserName, service)), nil
					}
				}
				return body, err
			}
			got := doctorDoorwayState(t.Context(), env, services)
			if got.status != statusFail || !strings.Contains(got.detail, "without bind readiness") || !strings.Contains(got.remediation, remedy) {
				t.Fatalf("legacy definition = %+v", got)
			}
			if status, _ := probeManagedDoorwaySockets(t.Context(), env, services); status != statusFail {
				t.Fatalf("legacy verification = %s", status)
			}
		})
	}
}

func TestNamespaceForwarderReadinessObservationErrors(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		code      int
		err       error
	}{
		{name: "execution failure", err: errors.New("systemctl unavailable")},
		{name: "manager failure", out: testForwarderReady, code: 1},
		{name: "malformed restart counter", out: "ActiveState=active\nSubState=running\nType=notify\nNRestarts=-1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := diagnosticDoorwayEnv(nil)
			oldRun := env.runCmd
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if name == "systemctl" && len(args) > 1 && args[0] == "show" {
					return tc.out, tc.code, tc.err
				}
				return oldRun(ctx, name, args...)
			}
			got := doctorDoorwayState(t.Context(), env, nil)
			if got.status != statusUnknown {
				t.Fatalf("inconclusive observation = %+v", got)
			}
			if status, _ := probeManagedDoorwaySockets(t.Context(), env, nil); status != statusFail {
				t.Fatalf("verify failed open: %s", status)
			}
		})
	}
}
