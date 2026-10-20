// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testDoorwayProxySocket = "pipelock-agent-proxy.socket"
	testDoorwayProxyRelay  = "pipelock-agent-proxy.service"
)

// fakeUnitState is one unit's scripted systemctl answers.
type fakeUnitState struct {
	enabled string
	active  string
}

// doorwayReaderFor drives doctorDoorwaySocketReader against scripted
// systemctl state. Units not named in states read as enabled and active. It
// records every unit queried so tests can assert what doctor looked at.
func doorwayReaderFor(states map[string]fakeUnitState, runErr error) (func() doctorResult, *[]string) {
	var queried []string
	base := diagnosticDoorwayEnv(states)
	base.configPath = "/etc/pipelock/pipelock.yaml"
	base.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if runErr != nil {
			return "", -1, runErr
		}
		if name != "systemctl" || len(args) != 2 {
			return "", 1, errors.New("unexpected command")
		}
		if args[0] == "is-active" {
			queried = append(queried, args[1])
		}
		st, ok := states[args[1]]
		if !ok {
			st = fakeUnitState{enabled: systemctlEnabled, active: systemctlActive}
		}
		// systemctl exits 0 only for an enabled or active unit.
		state, ok := st.active, st.active == systemctlActive
		if args[0] == "is-enabled" {
			state, ok = st.enabled, st.enabled == systemctlEnabled
		}
		if !ok {
			return state + "\n", 1, nil
		}
		return state + "\n", 0, nil
	}
	reader := doctorDoorwaySocketReader(base, &doctorEnv{port: defaultProxyPort, agentUserName: testAgentUser})
	return func() doctorResult { return reader(context.Background()) }, &queried
}

func TestDoctorNamespaceForwarderStates(t *testing.T) {
	for _, tc := range []struct {
		name        string
		state       fakeUnitState
		wantStatus  string
		wantRemedy  string
		wantDetails []string
	}{
		{"active and enabled", fakeUnitState{systemctlEnabled, systemctlActive}, statusPass, "", nil},
		{"inactive", fakeUnitState{systemctlEnabled, "inactive"}, statusFail, "systemctl restart " + containedNamespaceForwarderUnit, []string{containedNamespaceForwarderUnit, "inactive"}},
		{"inactive and disabled", fakeUnitState{"disabled", "inactive"}, statusFail, "systemctl enable --now " + containedNamespaceForwarderUnit, []string{"inactive", "disabled"}},
		{"failed", fakeUnitState{systemctlEnabled, systemctlFailed}, statusFail, "systemctl reset-failed " + containedNamespaceForwarderUnit + " && systemctl restart " + containedNamespaceForwarderUnit, []string{"failed"}},
		{"masked", fakeUnitState{systemctlMasked, "inactive"}, statusFail, "systemctl unmask " + containedNamespaceForwarderUnit + " && systemctl enable --now " + containedNamespaceForwarderUnit, []string{"masked"}},
		{"not found", fakeUnitState{systemctlNotFound, "inactive"}, statusFail, "pipelock contain install", []string{"not-found"}},
		{"active but not enabled", fakeUnitState{"disabled", systemctlActive}, statusFail, "systemctl enable --now " + containedNamespaceForwarderUnit, []string{"disabled"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read, _ := doorwayReaderFor(map[string]fakeUnitState{containedNamespaceForwarderUnit: tc.state}, nil)
			got := read()
			if got.status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (%+v)", got.status, tc.wantStatus, got)
			}
			if tc.wantStatus == statusPass {
				return
			}
			if !strings.Contains(got.remediation, tc.wantRemedy) {
				t.Fatalf("remediation = %q, want it to contain %q", got.remediation, tc.wantRemedy)
			}
			for _, want := range tc.wantDetails {
				if !strings.Contains(got.detail, want) {
					t.Fatalf("detail = %q, want it to contain %q", got.detail, want)
				}
			}
			if got.class != classInfra {
				t.Fatalf("class = %q, want %q", got.class, classInfra)
			}
		})
	}
}

func TestDoctorNamespaceForwarderSystemctlUnavailableIsUnknown(t *testing.T) {
	read, _ := doorwayReaderFor(nil, errors.New("exec: systemctl: not found"))
	if got := read(); got.status != statusUnknown {
		t.Fatalf("status = %q, want %q (%+v)", got.status, statusUnknown, got)
	}
}

func TestDoctorDoorwaySocketRemedyMatchesRelayState(t *testing.T) {
	for _, tc := range []struct {
		name          string
		socket, relay fakeUnitState
		prefix, start string
	}{
		{"disabled socket live relay", fakeUnitState{"disabled", "inactive"}, fakeUnitState{"static", systemctlActive}, "", "systemctl enable --now " + testDoorwayProxySocket},
		{"disabled socket inactive relay", fakeUnitState{"disabled", "inactive"}, fakeUnitState{"static", "inactive"}, "", "systemctl enable --now " + testDoorwayProxySocket},
		{"inactive enabled socket live relay", fakeUnitState{systemctlEnabled, "inactive"}, fakeUnitState{"static", systemctlActive}, "", "systemctl start " + testDoorwayProxySocket},
		{"failed socket live relay", fakeUnitState{systemctlEnabled, systemctlFailed}, fakeUnitState{"static", systemctlActive}, "", "systemctl reset-failed " + testDoorwayProxySocket + " && systemctl start " + testDoorwayProxySocket},
		{"masked socket inactive relay", fakeUnitState{systemctlMasked, "inactive"}, fakeUnitState{"static", "inactive"}, "systemctl unmask " + testDoorwayProxySocket + " && ", "systemctl enable --now " + testDoorwayProxySocket},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read, _ := doorwayReaderFor(map[string]fakeUnitState{testDoorwayProxySocket: tc.socket, testDoorwayProxyRelay: tc.relay}, nil)
			got := read()
			want := tc.prefix + "systemctl stop " + testDoorwayProxySocket + " && systemctl stop " + testDoorwayProxyRelay + " && " + tc.start + " && systemctl restart " + containedNamespaceForwarderUnit
			if got.status != statusFail || got.remediation != want {
				t.Fatalf("result=%+v want remediation %q", got, want)
			}
			if strings.Contains(got.detail, "run `systemctl") {
				t.Fatalf("detail embeds remedy: %s", got.detail)
			}
		})
	}
}

func TestDoctorDoorwayHealthyQueriesProxySocketAndForwarder(t *testing.T) {
	read, queried := doorwayReaderFor(nil, nil)
	got := read()
	if got.status != statusPass {
		t.Fatalf("status = %q, want pass (%+v)", got.status, got)
	}
	want := []string{testDoorwayProxySocket, testDoorwayProxyRelay, containedNamespaceForwarderUnit}
	if strings.Join(*queried, ",") != strings.Join(want, ",") {
		t.Fatalf("units queried = %v, want %v", *queried, want)
	}
}

// diagnosticDoorwayEnv models the installed definitions and a real socket type.
func diagnosticDoorwayEnv(states map[string]fakeUnitState) *probeEnv {
	env := &probeEnv{
		agentUserName: testAgentUser, proxyUserName: "pipelock-proxy", port: defaultProxyPort,
		proxyForwarderSocketPath:      "/etc/systemd/system/" + testDoorwayProxySocket,
		proxyForwarderServicePath:     "/etc/systemd/system/" + testDoorwayProxyRelay,
		namespaceForwarderServicePath: "/etc/systemd/system/" + containedNamespaceForwarderUnit,
		lstat:                         func(string) (os.FileInfo, error) { return fakeFileInfo{mode: os.ModeSocket | 0o600}, nil },
	}
	env.readFile = func(path string) ([]byte, error) {
		switch filepath.Base(path) {
		case testDoorwayProxySocket:
			return []byte(renderContainedProxySocketUnit(env.agentUserName)), nil
		case testDoorwayProxyRelay:
			return []byte(renderContainedProxyForwarderUnitTo(env.pipelockTarget, env.proxyUserName, containedRelayTarget(env.configPath, env.port))), nil
		case containedNamespaceForwarderUnit:
			return []byte(renderContainedNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, env.port)), nil
		}
		return nil, os.ErrNotExist
	}
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name != "systemctl" || len(args) != 2 || (args[0] != "is-enabled" && args[0] != "is-active") {
			return "", -1, errors.New("diagnostic attempted mutation")
		}
		st, ok := states[args[1]]
		if !ok {
			st = fakeUnitState{systemctlEnabled, systemctlActive}
		}
		if args[0] == "is-enabled" {
			return st.enabled, 0, nil
		}
		return st.active, 0, nil
	}
	return env
}

func TestDoorwayDiagnosticsRuntimeParity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		states  map[string]fakeUnitState
		pathErr error
		mode    os.FileMode
		want    string
	}{
		{name: "active socket missing path", pathErr: os.ErrNotExist, want: "missing"},
		{name: "active socket regular file", mode: 0o600, want: "not a socket"},
		{name: "active socket failed relay", mode: os.ModeSocket, states: map[string]fakeUnitState{testDoorwayProxyRelay: {"static", systemctlFailed}}, want: "relay"},
		{name: "stopped namespace forwarder", mode: os.ModeSocket, states: map[string]fakeUnitState{containedNamespaceForwarderUnit: {systemctlEnabled, "inactive"}}, want: "namespace forwarder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := diagnosticDoorwayEnv(tc.states)
			env.lstat = func(string) (os.FileInfo, error) { return fakeFileInfo{mode: tc.mode}, tc.pathErr }
			got := doctorDoorwayState(context.Background(), env, nil)
			status, detail := probeManagedDoorwaySockets(context.Background(), env, nil)
			if got.status != statusFail || status != statusFail || !strings.Contains(got.detail, tc.want) || !strings.Contains(detail, got.detail) || !strings.Contains(detail, got.remediation) {
				t.Fatalf("doctor=%+v verify=(%s,%s)", got, status, detail)
			}
		})
	}
}

func TestDoorwayDiagnosticsObservations(t *testing.T) {
	for _, tc := range []struct {
		name, unit, enabled, active, want string
		wantStatus                        string
	}{
		{"healthy inactive relay", testDoorwayProxyRelay, "static", "inactive", "enabled and active", statusPass},
		{"failed socket", testDoorwayProxySocket, systemctlEnabled, systemctlFailed, "reset-failed " + testDoorwayProxySocket, statusFail},
		{"masked socket", testDoorwayProxySocket, systemctlMasked, "inactive", "unmask " + testDoorwayProxySocket, statusFail},
		{"masked relay", testDoorwayProxyRelay, systemctlMasked, "inactive", "unmask " + testDoorwayProxyRelay, statusFail},
		{"failed relay", testDoorwayProxyRelay, "static", systemctlFailed, "reset-failed " + testDoorwayProxyRelay, statusFail},
		{"masked forwarder", containedNamespaceForwarderUnit, systemctlMasked, "inactive", "unmask " + containedNamespaceForwarderUnit, statusFail},
		{"failed forwarder", containedNamespaceForwarderUnit, systemctlEnabled, systemctlFailed, "reset-failed " + containedNamespaceForwarderUnit, statusFail},
		{"missing forwarder", containedNamespaceForwarderUnit, systemctlNotFound, "inactive", "pipelock contain install", statusFail},
		{"unknown relay", testDoorwayProxyRelay, "static", "future-state", "unrecognized state", statusUnknown},
		{"empty state", testDoorwayProxySocket, "", "", "could not be read", statusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := diagnosticDoorwayEnv(map[string]fakeUnitState{tc.unit: {tc.enabled, tc.active}})
			run := env.runCmd
			calls := map[string]int{}
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if name != "systemctl" || len(args) != 2 || (args[0] != "is-enabled" && args[0] != "is-active") {
					t.Fatalf("diagnostic attempted mutation: %s %v", name, args)
				}
				calls[strings.Join(args, " ")]++
				return run(ctx, name, args...)
			}
			got := doctorDoorwayState(context.Background(), env, nil)
			if got.status != tc.wantStatus || !strings.Contains(got.detail+got.remediation, tc.want) {
				t.Fatalf("result=%+v", got)
			}
			for query, count := range calls {
				if count != 1 {
					t.Fatalf("observation %s made %d times", query, count)
				}
			}
			for query := range calls {
				delete(calls, query)
			}
			again := doctorDoorwayState(context.Background(), env, nil)
			if got != again {
				t.Fatalf("repeated observation changed result: %+v -> %+v", got, again)
			}
		})
	}
}

func TestDoorwayDiagnosticsUnavailableAndDefinitions(t *testing.T) {
	for _, tc := range []struct {
		name         string
		change       func(*probeEnv)
		status, want string
	}{
		{"unreadable pathname", func(e *probeEnv) { e.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission } }, statusUnknown, "could not be read"},
		{"no pathname reader", func(e *probeEnv) { e.lstat = nil }, statusUnknown, "unavailable"},
		{"drifted definition", func(e *probeEnv) {
			e.readFile = func(string) ([]byte, error) { return []byte("operator override"), nil }
		}, statusFail, "pipelock contain install"},
		{"missing definition", func(e *probeEnv) { e.readFile = func(string) ([]byte, error) { return nil, os.ErrNotExist } }, statusFail, "pipelock contain install"},
		{"arbitrary unit text", func(e *probeEnv) { e.proxyForwarderSocketPath = "/etc/systemd/system/untrusted;touch marker.socket" }, statusFail, "canonical"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := diagnosticDoorwayEnv(nil)
			tc.change(env)
			result := doctorDoorwayState(context.Background(), env, nil)
			if result.status != tc.status || !strings.Contains(result.detail+result.remediation, tc.want) {
				t.Fatalf("result=%+v", result)
			}
			if strings.Contains(result.remediation, "untrusted") || strings.Contains(result.remediation, "touch marker") {
				t.Fatalf("untrusted command: %+v", result)
			}
		})
	}
	for _, unit := range []string{testDoorwayProxySocket, testDoorwayProxyRelay, containedNamespaceForwarderUnit} {
		t.Run("unreadable "+unit, func(t *testing.T) {
			env := diagnosticDoorwayEnv(nil)
			run := env.runCmd
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if args[1] == unit {
					return "", -1, os.ErrPermission
				}
				return run(ctx, name, args...)
			}
			if result := doctorDoorwayState(context.Background(), env, nil); result.status != statusUnknown {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestDoorwayDiagnosticsLoopbackSibling(t *testing.T) {
	env := covNSProbeBase(t)
	services := []config.ContainmentLoopbackService{{Host: "127.0.0.1", Port: 9200}, {Host: "::1", Port: 9201}}
	for _, service := range services {
		writeLoopbackProbeUnits(t, env, service)
	}
	env.lstat = func(path string) (os.FileInfo, error) {
		if path == declaredLoopbackDoorwayPath("::1", 9201) {
			return nil, os.ErrNotExist
		}
		return fakeFileInfo{mode: os.ModeSocket}, nil
	}
	result := doctorDoorwayState(context.Background(), env, services)
	if result.status != statusFail || !strings.Contains(result.detail, "v6-9201") || !strings.Contains(result.remediation, "systemctl restart "+loopbackForwarderUnitBase("::1", 9201)+"-netns.service") {
		t.Fatalf("result=%+v", result)
	}
	if strings.Contains(result.remediation, "9200") {
		t.Fatalf("sibling recovery changed another doorway: %+v", result)
	}
}

func TestDoorwayRecoveryMissingOrFailedForwarder(t *testing.T) {
	for _, state := range []fakeUnitState{{systemctlNotFound, "inactive"}, {systemctlMasked, systemctlFailed}} {
		t.Run(state.enabled, func(t *testing.T) {
			env := diagnosticDoorwayEnv(map[string]fakeUnitState{containedNamespaceForwarderUnit: state})
			env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
			result := doctorDoorwayState(context.Background(), env, nil)
			if state.enabled == systemctlNotFound {
				if result.remediation != installRemedy {
					t.Fatalf("result=%+v", result)
				}
				return
			}
			want := "systemctl start " + testDoorwayProxySocket + " && systemctl unmask " + containedNamespaceForwarderUnit + " && systemctl reset-failed " + containedNamespaceForwarderUnit + " && systemctl enable --now " + containedNamespaceForwarderUnit
			if !strings.HasSuffix(result.remediation, want) {
				t.Fatalf("result=%+v", result)
			}
		})
	}
	env := diagnosticDoorwayEnv(nil)
	run := env.runCmd
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if args[0] == "is-active" {
			return "", -1, os.ErrPermission
		}
		return run(ctx, name, args...)
	}
	if result := doctorDoorwayState(context.Background(), env, nil); result.status != statusUnknown {
		t.Fatalf("result=%+v", result)
	}
}

func TestDoorwaySocketPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket pathname inspection requires a Unix host")
	}
	path := filepath.Join(t.TempDir(), "doorway.sock")
	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	env := diagnosticDoorwayEnv(nil)
	env.lstat = func(string) (os.FileInfo, error) { return os.Lstat(path) }
	if result := doctorDoorwayState(context.Background(), env, nil); result.status != statusPass {
		t.Fatalf("positive control=%+v", result)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	result := doctorDoorwayState(context.Background(), env, nil)
	if result.status != statusFail || !strings.Contains(result.detail, "missing despite an active socket unit") {
		t.Fatalf("unlinked live listener=%+v", result)
	}
}

func TestDoorwayRuntimeMaskRecovery(t *testing.T) {
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9200}
	for _, base := range []string{containedProxyForwarderUnit, loopbackForwarderUnitBase(service.Host, service.Port)} {
		for _, suffix := range []string{".socket", ".service", "-netns.service"} {
			unit := base + suffix
			forwarder := base + "-netns.service"
			if base == containedProxyForwarderUnit {
				forwarder = containedNamespaceForwarderUnit
				if suffix == "-netns.service" {
					unit = forwarder
				}
			}
			t.Run(unit, func(t *testing.T) {
				env := covNSProbeBase(t)
				writeLoopbackProbeUnits(t, env, service)
				run := env.runCmd
				env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
					if args[1] == unit {
						if args[0] == "is-enabled" {
							return systemctlMasked + "-runtime", 1, nil
						}
						return systemctlInactive, 3, nil
					}
					return run(ctx, name, args...)
				}
				want := "systemctl unmask --runtime " + unit + " && "
				if suffix == "-netns.service" {
					want += "systemctl enable --now " + unit
				} else {
					want += "systemctl stop " + base + ".socket && systemctl stop " + base + ".service && "
					if suffix == ".socket" {
						want += "systemctl enable --now "
					} else {
						want += "systemctl start "
					}
					want += base + ".socket && systemctl restart " + forwarder
				}
				services := []config.ContainmentLoopbackService{service}
				got := doctorDoorwayState(context.Background(), env, services)
				status, detail := probeManagedDoorwaySockets(context.Background(), env, services)
				if got.status != statusFail || got.remediation != want || status != statusFail || !strings.Contains(detail, want) {
					t.Fatalf("doctor=%+v verify=(%s,%s), want %q", got, status, detail, want)
				}
			})
		}
	}
}

func TestDoorwayRelayTransitionsRemainInconclusive(t *testing.T) {
	for _, state := range []string{"activating", "deactivating", "reloading"} {
		t.Run(state, func(t *testing.T) {
			env := diagnosticDoorwayEnv(map[string]fakeUnitState{testDoorwayProxyRelay: {"static", state}})
			got := doctorDoorwayState(context.Background(), env, nil)
			status, detail := probeManagedDoorwaySockets(context.Background(), env, nil)
			want := "rerun the diagnostic after the relay finishes changing state"
			if got.status != statusUnknown || got.remediation != want || !strings.Contains(got.detail, state) || status != statusFail || !strings.Contains(detail, want) {
				t.Fatalf("doctor=%+v verify=(%s,%s)", got, status, detail)
			}
		})
	}
}
