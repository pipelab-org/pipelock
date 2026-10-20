// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDoorwayPathFindingsRetainUnitFailures(t *testing.T) {
	for _, pathState := range []string{"unavailable", "permission", "non-socket"} {
		for _, unit := range []string{testDoorwayProxyRelay, containedNamespaceForwarderUnit} {
			t.Run(pathState+"/"+unit, func(t *testing.T) {
				env := diagnosticDoorwayEnv(map[string]fakeUnitState{unit: {systemctlEnabled, systemctlFailed}})
				switch pathState {
				case "unavailable":
					env.lstat = nil
				case "permission":
					env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
				case "non-socket":
					env.lstat = func(string) (os.FileInfo, error) { return fakeFileInfo{}, nil }
				}
				got := doctorDoorwayState(t.Context(), env, nil)
				if got.status != statusFail || !strings.Contains(got.detail, "pathname") || !strings.Contains(got.detail, unit+" is failed") || !strings.Contains(got.remediation, "systemctl reset-failed "+unit) {
					t.Fatalf("pathname finding hid independent unit failure: %+v", got)
				}
				if status, _ := probeManagedDoorwaySockets(t.Context(), env, nil); status != statusFail {
					t.Fatalf("verification failed open: %s", status)
				}
			})
		}
	}
}

func TestDoorwayBadRelayRetainsOtherFailures(t *testing.T) {
	for _, unit := range []string{testDoorwayProxySocket, containedNamespaceForwarderUnit} {
		t.Run(unit, func(t *testing.T) {
			env := diagnosticDoorwayEnv(map[string]fakeUnitState{
				testDoorwayProxyRelay: {"bad", "inactive"}, unit: {systemctlEnabled, systemctlFailed},
			})
			got := doctorDoorwayState(t.Context(), env, nil)
			if got.status != statusFail || !strings.Contains(got.detail, "(bad)") || !strings.Contains(got.detail, unit+" is failed") || !strings.Contains(got.remediation, installRemedy) || !strings.Contains(got.remediation, "systemctl reset-failed "+unit) {
				t.Fatalf("invalid relay hid independent unit failure: %+v", got)
			}
		})
	}
}

func TestDoorwayUnreadableUnitRetainsOtherFailures(t *testing.T) {
	for _, unreadable := range []string{testDoorwayProxySocket, testDoorwayProxyRelay, containedNamespaceForwarderUnit} {
		for _, broken := range []string{testDoorwayProxySocket, testDoorwayProxyRelay, containedNamespaceForwarderUnit} {
			if unreadable == broken {
				continue
			}
			t.Run(unreadable+"/"+broken, func(t *testing.T) {
				env := diagnosticDoorwayEnv(map[string]fakeUnitState{broken: {systemctlEnabled, systemctlFailed}})
				run := env.runCmd
				env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
					if args[1] == unreadable {
						return "", -1, os.ErrPermission
					}
					return run(ctx, name, args...)
				}
				got := doctorDoorwayState(t.Context(), env, nil)
				if got.status != statusFail || !strings.Contains(got.detail, unreadable+" state could not be read") || !strings.Contains(got.detail, broken+" is failed") {
					t.Fatalf("unreadable unit hid independent failure: %+v", got)
				}
				if strings.Contains(got.remediation, "systemctl stop "+unreadable) || strings.Contains(got.remediation, "systemctl restart "+unreadable) || strings.Contains(got.remediation, "systemctl enable --now "+unreadable) {
					t.Fatalf("unobserved unit acquired recovery commands: %+v", got)
				}
			})
		}
	}
}

func TestDoorwayTransitionsNeverReceiveRuntimeRepair(t *testing.T) {
	for _, unit := range []string{testDoorwayProxySocket, containedNamespaceForwarderUnit} {
		for _, enabled := range []string{systemctlEnabled, "disabled", systemctlMasked, systemctlMasked + "-runtime", "enabled-runtime"} {
			for _, active := range []string{"activating", "deactivating", "reloading", "refreshing", "maintenance"} {
				for _, socketFailed := range []bool{false, true} {
					if unit == testDoorwayProxySocket && socketFailed {
						continue
					}
					t.Run(unit+"/"+enabled+"/"+active+map[bool]string{false: "/alone", true: "/socket-failed"}[socketFailed], func(t *testing.T) {
						states := map[string]fakeUnitState{unit: {enabled, active}}
						if socketFailed {
							states[testDoorwayProxySocket] = fakeUnitState{systemctlEnabled, systemctlFailed}
						}
						got := doctorDoorwayState(t.Context(), diagnosticDoorwayEnv(states), nil)
						if got.status == statusPass || !strings.Contains(got.detail, active) || !strings.Contains(got.remediation, "finishes changing state") {
							t.Fatalf("transition lost: %+v", got)
						}
						for _, command := range []string{"stop", "start", "restart", "enable --now", "unmask", "unmask --runtime"} {
							if strings.Contains(got.remediation, "systemctl "+command+" "+unit) {
								t.Fatalf("transition acquired runtime repair: %+v", got)
							}
						}
						if unit == containedNamespaceForwarderUnit && strings.Contains(got.remediation, "systemctl stop "+testDoorwayProxySocket) {
							t.Fatalf("socket recovery would stop the transitioning dependent forwarder: %+v", got)
						}
					})
				}
			}
		}
	}
}

func TestDoorwayRelayOnlyRecoveryPreservesSocket(t *testing.T) {
	for _, relay := range []fakeUnitState{{"static", systemctlFailed}, {systemctlMasked, "inactive"}, {systemctlMasked + "-runtime", systemctlFailed}} {
		t.Run(relay.enabled+"/"+relay.active, func(t *testing.T) {
			got := doctorDoorwayState(t.Context(), diagnosticDoorwayEnv(map[string]fakeUnitState{testDoorwayProxyRelay: relay}), nil)
			if got.status != statusFail || strings.Contains(got.remediation, testDoorwayProxySocket) || strings.Contains(got.remediation, "systemctl stop "+testDoorwayProxyRelay) {
				t.Fatalf("relay-only recovery interrupted healthy listener: %+v", got)
			}
			if relay.active == systemctlFailed && !strings.Contains(got.remediation, "systemctl reset-failed "+testDoorwayProxyRelay) {
				t.Fatalf("relay start limit not reset: %+v", got)
			}
		})
	}
}

func TestDoorwayDefinitionRepairMatchesSupportedCommand(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		for _, suffix := range []string{".socket", ".service", "-netns.service"} {
			for _, readError := range []bool{false, true} {
				t.Run(map[bool]string{false: "loopback", true: "proxy"}[proxy]+suffix+map[bool]string{false: "/drift", true: "/unreadable"}[readError], func(t *testing.T) {
					env := covNSProbeBase(t)
					service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9200}
					writeLoopbackProbeUnits(t, env, service)
					base := loopbackForwarderUnitBase(service.Host, service.Port)
					path, remedy := filepath.Join(filepath.Dir(env.proxyForwarderSocketPath), base+suffix), "rerun `pipelock contain reload-nft-rules`"
					if proxy {
						path, remedy = env.proxyForwarderSocketPath, installRemedy
						switch suffix {
						case ".service":
							path = env.proxyForwarderServicePath
						case "-netns.service":
							path = env.namespaceForwarderServicePath
						}
					}
					read := env.readFile
					env.readFile = func(name string) ([]byte, error) {
						if name == path {
							if readError {
								return nil, os.ErrPermission
							}
							return []byte("operator override"), nil
						}
						return read(name)
					}
					got := doctorDoorwayState(t.Context(), env, []config.ContainmentLoopbackService{service})
					if got.status != statusFail || got.remediation != remedy || !strings.Contains(got.detail, path) {
						t.Fatalf("unsupported definition repair: %+v, want %s", got, remedy)
					}
				})
			}
		}
	}
}

func TestDoorwaySocketRecoveryRestoresRequiredForwarder(t *testing.T) {
	if !strings.Contains(renderContainedNamespaceForwarderUnit("/usr/bin/pipelock", "agent", defaultProxyPort), "Requires="+testDoorwayProxySocket) {
		t.Fatal("fixture no longer models the managed forwarder's socket dependency")
	}
	env := diagnosticDoorwayEnv(nil)
	env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	got := doctorDoorwayState(t.Context(), env, nil)
	if got.status != statusFail {
		t.Fatalf("missing pathname was not diagnosed: %+v", got)
	}
	active := map[string]bool{
		testDoorwayProxySocket: true, testDoorwayProxyRelay: true, containedNamespaceForwarderUnit: true,
	}
	for _, command := range strings.Split(got.remediation, " && ") {
		args := strings.Fields(command)
		if len(args) != 3 || args[0] != "systemctl" {
			t.Fatalf("unexpected recovery command: %q", command)
		}
		switch args[1] {
		case "stop":
			active[args[2]] = false
			if args[2] == testDoorwayProxySocket {
				// systemd.unit(5), Requires=: explicitly stopping the
				// required socket also stops its dependent forwarder.
				active[containedNamespaceForwarderUnit] = false
			}
		case "start":
			// Starting the required socket has no reverse dependency
			// that starts its dependent namespace forwarder.
			active[args[2]] = true
		default:
			t.Fatalf("unexpected recovery verb: %q", command)
		}
	}
	if !active[testDoorwayProxySocket] || !active[containedNamespaceForwarderUnit] {
		t.Fatalf("suggested recovery left the namespace listener down: active=%v, result=%+v", active, got)
	}
}

func TestDoorwaySocketRecoveryWaitsForRelayTransition(t *testing.T) {
	for _, active := range []string{"activating", "deactivating", "reloading", "refreshing", "maintenance"} {
		t.Run(active, func(t *testing.T) {
			env := diagnosticDoorwayEnv(map[string]fakeUnitState{
				testDoorwayProxySocket: {systemctlEnabled, "inactive"},
				testDoorwayProxyRelay:  {"static", active},
			})
			got := doctorDoorwayState(t.Context(), env, nil)
			if got.status != statusFail || !strings.Contains(got.detail, active) || !strings.Contains(got.remediation, "relay finishes changing state") || strings.Contains(got.remediation, "systemctl stop") {
				t.Fatalf("socket recovery interrupted relay transition: %+v", got)
			}
		})
	}
}

func TestDoorwayRecoveryUnitFileStatesProduceCompleteCommands(t *testing.T) {
	for _, enabled := range []string{"enabled-runtime", "linked", "static"} {
		t.Run(enabled, func(t *testing.T) {
			env := diagnosticDoorwayEnv(map[string]fakeUnitState{containedNamespaceForwarderUnit: {enabled, systemctlActive}})
			env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
			got := doctorDoorwayState(t.Context(), env, nil)
			if got.status != statusFail {
				t.Fatalf("nonpersistent forwarder and absent pathname passed: %+v", got)
			}
			for _, command := range strings.Split(got.remediation, " && ") {
				if len(strings.Fields(command)) < 3 || !strings.HasPrefix(command, "systemctl ") {
					t.Fatalf("incomplete recovery command %q: %+v", command, got)
				}
			}
			if !strings.HasSuffix(got.remediation, "systemctl enable --now "+containedNamespaceForwarderUnit) {
				t.Fatalf("forwarder repair omitted: %+v", got)
			}
			t.Logf("%s: %s", enabled, got.remediation)
		})
	}
}
