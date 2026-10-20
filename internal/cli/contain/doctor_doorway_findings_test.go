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

func TestDoorwayRecoveryPreservesHealthyNamespaceForwarder(t *testing.T) {
	env := diagnosticDoorwayEnv(map[string]fakeUnitState{testDoorwayProxySocket: {systemctlEnabled, "inactive"}})
	got := doctorDoorwayState(t.Context(), env, nil)
	if got.status != statusFail || !strings.Contains(got.remediation, "systemctl stop "+testDoorwayProxySocket+" && systemctl stop "+testDoorwayProxyRelay) {
		t.Fatalf("socket-before-relay repair lost: %+v", got)
	}
	if strings.Contains(got.remediation, containedNamespaceForwarderUnit) {
		t.Fatalf("healthy namespace forwarder would be interrupted: %+v", got)
	}
}

func TestDoorwayFailuresRetainLaterMissingForwarder(t *testing.T) {
	env := covNSProbeBase(t)
	services := []config.ContainmentLoopbackService{{Host: "127.0.0.1", Port: 9200}, {Host: "::1", Port: 9201}}
	for _, service := range services {
		writeLoopbackProbeUnits(t, env, service)
	}
	firstPath := declaredLoopbackDoorwayPath(services[0].Host, services[0].Port)
	laterForwarder := loopbackForwarderUnitBase(services[1].Host, services[1].Port) + "-netns.service"
	env.lstat = func(path string) (os.FileInfo, error) {
		if path == firstPath {
			return nil, os.ErrNotExist
		}
		return fakeFileInfo{mode: os.ModeSocket}, nil
	}
	run := env.runCmd
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if len(args) == 2 && args[1] == laterForwarder {
			if args[0] == "is-enabled" {
				return systemctlNotFound, 1, nil
			}
			return "inactive", 3, nil
		}
		return run(ctx, name, args...)
	}
	got := doctorDoorwayState(t.Context(), env, services)
	if got.status != statusFail || !strings.Contains(got.detail, firstPath) || !strings.Contains(got.detail, laterForwarder) || !strings.Contains(got.remediation, installRemedy) {
		t.Fatalf("later independent failure was hidden: %+v", got)
	}
}

func TestDoorwayAggregationSeverityAndOrder(t *testing.T) {
	for _, tc := range []struct {
		first, second, want string
	}{
		{statusPass, statusPass, statusPass},
		{statusUnknown, statusPass, statusUnknown},
		{statusPass, statusUnknown, statusUnknown},
		{statusUnknown, statusUnknown, statusUnknown},
		{statusFail, statusPass, statusFail},
		{statusPass, statusFail, statusFail},
		{statusFail, statusUnknown, statusFail},
		{statusUnknown, statusFail, statusFail},
		{statusFail, statusFail, statusFail},
	} {
		t.Run(tc.first+"/"+tc.second, func(t *testing.T) {
			env := covNSProbeBase(t)
			services := []config.ContainmentLoopbackService{{Host: "127.0.0.1", Port: 9200}, {Host: "::1", Port: 9201}}
			states := map[string]string{}
			for i, service := range services {
				writeLoopbackProbeUnits(t, env, service)
				states[declaredLoopbackDoorwayPath(service.Host, service.Port)] = []string{tc.first, tc.second}[i]
			}
			env.lstat = func(path string) (os.FileInfo, error) {
				switch states[path] {
				case statusFail:
					return nil, os.ErrNotExist
				case statusUnknown:
					return nil, os.ErrPermission
				}
				return fakeFileInfo{mode: os.ModeSocket}, nil
			}
			got := doctorDoorwayState(t.Context(), env, services)
			if got.status != tc.want || tc.want != statusPass && got.class != classInfra {
				t.Fatalf("result=%+v, want %s", got, tc.want)
			}
			for path, state := range states {
				if state != statusPass && !strings.Contains(got.detail, path) {
					t.Fatalf("independent %s observation for %s was hidden: %+v", state, path, got)
				}
			}
			reversed := []config.ContainmentLoopbackService{services[1], services[0]}
			if again := doctorDoorwayState(t.Context(), env, reversed); again != got {
				t.Fatalf("configuration order changed diagnostic: %+v -> %+v", got, again)
			}
			status, detail := probeManagedDoorwaySockets(t.Context(), env, services)
			if tc.want == statusPass {
				if status != statusPass {
					t.Fatalf("healthy verify=(%s,%s)", status, detail)
				}
			} else if status != statusFail || !strings.Contains(detail, got.detail) || !strings.Contains(detail, got.remediation) {
				t.Fatalf("verify lost aggregate or failed open: (%s,%s), doctor=%+v", status, detail, got)
			}
		})
	}
}

func TestDoorwayUnverifiedDefinitionsDoNotSuggestUnitCommands(t *testing.T) {
	env := diagnosticDoorwayEnv(nil)
	env.readFile = func(string) ([]byte, error) { return []byte("operator override"), nil }
	env.runCmd = func(context.Context, string, ...string) (string, int, error) {
		t.Fatal("unverified definitions reached runtime unit inspection")
		return "", -1, os.ErrPermission
	}
	got := doctorDoorwayState(t.Context(), env, nil)
	if got.status != statusFail || got.class != classInfra || got.remediation != installRemedy || strings.Contains(got.remediation, "systemctl") {
		t.Fatalf("unverified definitions acquired recovery commands: %+v", got)
	}
}

func TestDoorwayUnknownRelayRetainsDefiniteFailures(t *testing.T) {
	for _, tc := range []struct {
		name, unit string
		state      fakeUnitState
		missing    bool
	}{
		{"disabled socket", testDoorwayProxySocket, fakeUnitState{"disabled", "inactive"}, false},
		{"inactive socket", testDoorwayProxySocket, fakeUnitState{systemctlEnabled, "inactive"}, false},
		{"missing pathname", "", fakeUnitState{}, true},
		{"inactive forwarder", containedNamespaceForwarderUnit, fakeUnitState{systemctlEnabled, "inactive"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := diagnosticDoorwayEnv(map[string]fakeUnitState{
				testDoorwayProxyRelay: {"future-state", systemctlActive}, tc.unit: tc.state,
			})
			if tc.missing {
				env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
			}
			got := doctorDoorwayState(t.Context(), env, nil)
			if got.status != statusFail || !strings.Contains(got.detail, "future-state") {
				t.Fatalf("unknown relay hid definite failure: %+v", got)
			}
			if status, _ := probeManagedDoorwaySockets(t.Context(), env, nil); status != statusFail {
				t.Fatalf("verification failed open: %s", status)
			}
		})
	}
}

func TestDoorwayDefinitionFailureRetainsVerifiedSiblingRuntime(t *testing.T) {
	for _, unreadable := range []bool{false, true} {
		t.Run(map[bool]string{false: "drift", true: "unreadable"}[unreadable], func(t *testing.T) {
			env := covNSProbeBase(t)
			service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9200}
			writeLoopbackProbeUnits(t, env, service)
			unit := loopbackForwarderUnitBase(service.Host, service.Port)
			read := env.readFile
			env.readFile = func(path string) ([]byte, error) {
				if filepath.Base(path) == unit+".service" {
					if unreadable {
						return nil, os.ErrPermission
					}
					return []byte("operator override"), nil
				}
				return read(path)
			}
			run := env.runCmd
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if len(args) == 2 && strings.HasPrefix(args[1], unit) {
					t.Fatal("unverified doorway reached runtime inspection")
				}
				if len(args) == 2 && args[1] == testDoorwayProxySocket && args[0] == "is-active" {
					return "inactive", 3, nil
				}
				return run(ctx, name, args...)
			}
			got := doctorDoorwayState(t.Context(), env, []config.ContainmentLoopbackService{service})
			if got.status != statusFail || !strings.Contains(got.detail, unit+".service") || !strings.Contains(got.detail, testDoorwayProxySocket+" is inactive") || !strings.Contains(got.remediation, installRemedy) || !strings.Contains(got.remediation, "systemctl start "+testDoorwayProxySocket) {
				t.Fatalf("definition gate hid verified sibling failure: %+v", got)
			}
			if strings.Contains(got.remediation, "systemctl stop "+unit) {
				t.Fatalf("unverified doorway acquired runtime remedy: %+v", got)
			}
		})
	}
}

func TestDoorwaySocketAndForwarderTransitions(t *testing.T) {
	for _, unit := range []string{testDoorwayProxySocket, containedNamespaceForwarderUnit} {
		for _, state := range []string{"activating", "deactivating", "reloading"} {
			t.Run(unit+"/"+state, func(t *testing.T) {
				env := diagnosticDoorwayEnv(map[string]fakeUnitState{unit: {systemctlEnabled, state}})
				got := doctorDoorwayState(t.Context(), env, nil)
				if got.status != statusUnknown || !strings.Contains(got.detail, unit) || strings.Contains(got.remediation, "systemctl") {
					t.Fatalf("transition suggested disruptive repair: %+v", got)
				}
				if status, _ := probeManagedDoorwaySockets(t.Context(), env, nil); status != statusFail {
					t.Fatalf("transition verification failed open: %s", status)
				}
			})
		}
	}
}

func TestDoorwaySocketFailureDoesNotRestartTransitioningForwarder(t *testing.T) {
	env := diagnosticDoorwayEnv(map[string]fakeUnitState{
		testDoorwayProxySocket:          {systemctlEnabled, "inactive"},
		containedNamespaceForwarderUnit: {systemctlEnabled, "activating"},
	})
	got := doctorDoorwayState(t.Context(), env, nil)
	if got.status != statusFail || strings.Contains(got.remediation, "systemctl restart "+containedNamespaceForwarderUnit) || !strings.Contains(got.detail, "activating") {
		t.Fatalf("socket repair interrupted transitioning forwarder: %+v", got)
	}
}
