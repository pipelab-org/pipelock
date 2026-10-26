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

// priorReleaseForwarderUnits are namespace forwarder definitions as the last
// release before bind readiness rendered them for the fixture arguments below,
// with the host-selected runtime mounts replaced by {{MOUNTS}}.
const priorReleaseProxyForwarderUnit = `[Unit]
Description=Pipelock proxy listener inside the contained-agent network namespace
Requires=pipelock-agent-netns.service
After=pipelock-agent-netns.service
Requires=pipelock-agent-proxy.socket
After=pipelock-agent-proxy.socket
JoinsNamespaceOf=pipelock-agent-netns.service

[Service]
Type=simple
User=agent
Group=agent
ExecStart=/usr/local/bin/pipelock contain netns-forward --listen 127.0.0.1:8888 --target /run/pipelock-agent-proxy/doorway.sock
{{MOUNTS}}
BindReadOnlyPaths=/run/pipelock-agent-proxy
PrivateNetwork=true
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
Restart=on-failure

[Install]
WantedBy=multi-user.target
`

const priorReleaseDeclaredForwarderUnit = `[Unit]
Description=Pipelock declared loopback listener inside the contained-agent network namespace
Requires=pipelock-agent-netns.service
After=pipelock-agent-netns.service
Requires=pipelock-agent-loopback-v4-5432.socket
After=pipelock-agent-loopback-v4-5432.socket
JoinsNamespaceOf=pipelock-agent-netns.service

[Service]
Type=simple
User=agent
Group=agent
ExecStart=/usr/local/bin/pipelock contain netns-forward --listen 127.0.0.1:5432 --target /run/pipelock-agent-loopback-v4-5432/doorway.sock
{{MOUNTS}}
BindReadOnlyPaths=/run/pipelock-agent-loopback-v4-5432
PrivateNetwork=true
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
Restart=on-failure

[Install]
WantedBy=multi-user.target
`

func TestLegacyNamespaceForwarderDefinitionMatchesPriorRelease(t *testing.T) {
	mounts := strings.Join(runtimeSocketMountProperties(), "\n")
	for name, tc := range map[string]struct{ current, prior string }{
		"proxy":    {renderContainedNamespaceForwarderUnit("/usr/local/bin/pipelock", "agent", 8888), priorReleaseProxyForwarderUnit},
		"declared": {renderDeclaredLoopbackNamespaceForwarderUnit("/usr/local/bin/pipelock", "agent", config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 5432}), priorReleaseDeclaredForwarderUnit},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := legacyNamespaceForwarderDefinition(tc.current)
			want := strings.Replace(tc.prior, "{{MOUNTS}}", mounts, 1)
			if !ok || got != want {
				t.Fatalf("derived legacy definition (ok=%t):\n%s\nwant:\n%s", ok, got, want)
			}
		})
	}
	if _, ok := legacyNamespaceForwarderDefinition(renderContainedProxySocketUnit("agent")); ok {
		t.Fatal("a unit without readiness directives has no legacy form")
	}
}

// TestLegacyNamespaceForwarderAfterBinaryUpgrade covers a host whose binary was
// replaced by `contain upgrade`, which does not rewrite doorway units. Final
// verification must accept the exact prior definition while it is running,
// keep naming the migration, and still refuse a restart-looping listener.
func TestLegacyNamespaceForwarderAfterBinaryUpgrade(t *testing.T) {
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9201}
	unit := loopbackForwarderUnitBase(service.Host, service.Port) + "-netns.service"
	timeout := fmt.Sprintf("TimeoutStartSec=%d\n", int64(cliutil.ServiceStartTimeout/time.Second))
	for _, declared := range []bool{false, true} {
		for _, tc := range []struct {
			name, active, sub, kind string
			hybrid                  bool
			want                    string
		}{
			{name: "prior definition running", active: "active", sub: "running", kind: "simple", want: statusPass},
			{name: "prior definition restart-looping", active: "activating", sub: "auto-restart", kind: "simple", want: statusFail},
			{name: "prior definition exited", active: "active", sub: "exited", kind: "simple", want: statusFail},
			{name: "prior definition other type", active: "active", sub: "running", kind: "forking", want: statusFail},
			{name: "hybrid simple definition", active: "active", sub: "running", kind: "simple", hybrid: true, want: statusFail},
		} {
			t.Run(fmt.Sprintf("declared=%t/%s", declared, tc.name), func(t *testing.T) {
				env := diagnosticDoorwayEnv(nil)
				oldRead, oldRun := env.readFile, env.runCmd
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
					switch filepath.Base(path) {
					case unit:
						body = []byte(renderDeclaredLoopbackNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, service))
					case strings.TrimSuffix(unit, "-netns.service") + ".socket":
						body = []byte(renderDeclaredLoopbackSocketUnit(env.agentUserName, service))
					case strings.TrimSuffix(unit, "-netns.service") + ".service":
						body = []byte(renderDeclaredLoopbackForwarderUnit(env.pipelockTarget, env.proxyUserName, service))
					default:
						body, err = oldRead(path)
					}
					if err != nil || filepath.Base(path) != target {
						return body, err
					}
					legacy, ok := legacyNamespaceForwarderDefinition(string(body))
					if !ok {
						t.Fatalf("no legacy form for %s", path)
					}
					if tc.hybrid {
						legacy = strings.Replace(legacy, "Type=simple\n", "Type=simple\n"+timeout, 1)
					}
					return []byte(legacy), nil
				}
				env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
					if name == "systemctl" && len(args) > 1 && args[1] == target {
						switch args[0] {
						case "is-enabled":
							return systemctlEnabled, 0, nil
						case "is-active":
							return tc.active, 0, nil
						case "show":
							return fmt.Sprintf("ActiveState=%s\nSubState=%s\nType=%s\nNRestarts=3\n", tc.active, tc.sub, tc.kind), 0, nil
						}
					}
					if name == "systemctl" && len(args) > 1 && args[0] == "show" {
						return testForwarderReady, 0, nil
					}
					if name == "systemctl" && len(args) > 1 && args[0] == "is-enabled" {
						return systemctlEnabled, 0, nil
					}
					if name == "systemctl" && len(args) > 1 && args[0] == "is-active" {
						return systemctlActive, 0, nil
					}
					return oldRun(ctx, name, args...)
				}
				got := doctorDoorwayState(t.Context(), env, services)
				status, detail := probeManagedDoorwaySockets(t.Context(), env, services)
				if got.status != tc.want || status != tc.want {
					t.Fatalf("doctor=%+v verify=%s %q; want %s", got, status, detail, tc.want)
				}
				switch {
				case tc.want == statusPass:
					for _, text := range []string{target, "without bind readiness", "contain install"} {
						if !strings.Contains(got.detail, text) || !strings.Contains(detail, text) {
							t.Fatalf("passing legacy listener hides %q: doctor=%q verify=%q", text, got.detail, detail)
						}
					}
				case tc.hybrid:
					if !strings.Contains(got.detail, "without bind readiness") || !strings.Contains(got.remediation, remedy) {
						t.Fatalf("hybrid definition = %+v", got)
					}
				default:
					if !strings.Contains(got.detail, target) {
						t.Fatalf("legacy runtime failure hides the listener: %+v", got)
					}
				}
			})
		}
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
