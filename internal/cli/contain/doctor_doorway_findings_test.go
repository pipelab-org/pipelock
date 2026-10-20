// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"os"
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
