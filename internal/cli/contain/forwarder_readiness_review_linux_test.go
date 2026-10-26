// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"os"
	"strings"
	"testing"
)

// renderedBindShow reports BindReadOnlyPaths the way `systemctl show --value`
// does for plain-path entries: each path becomes path:path:rbind. Deriving it
// from the rendered unit keeps the fake from agreeing with the check by
// construction.
func renderedBindShow(t *testing.T, unit string) string {
	t.Helper()
	var binds []string
	for _, line := range strings.Split(unit, "\n") {
		path, ok := strings.CutPrefix(line, "BindReadOnlyPaths=")
		if !ok {
			continue
		}
		if strings.Contains(path, ":") {
			t.Fatalf("fixture only models plain-path binds, got %q", line)
		}
		binds = append(binds, path+":"+path+":rbind")
	}
	if len(binds) == 0 {
		t.Fatal("rendered unit has no BindReadOnlyPaths")
	}
	return strings.Join(binds, " ")
}

func notifyBindShow() string {
	return systemdNotifySocketPath + ":" + systemdNotifySocketPath + ":rbind"
}

func TestDoctorRuntimeSocketsAcceptsRenderedForwarderBinds(t *testing.T) {
	wrapper := renderContainedLaunchWrapper(&installEnv{wrapperDir: "/fixture", networkNamespaceUnitPath: containedNetworkNamespaceUnit})
	unit := renderContainedNamespaceForwarderUnit("/usr/local/bin/pipelock", "pipelock-agent", defaultProxyPort)
	if !strings.Contains(unit, "BindReadOnlyPaths="+systemdNotifySocketPath+"\n") {
		t.Fatalf("forwarder fixture lacks the notify socket bind:\n%s", unit)
	}
	binds := renderedBindShow(t, unit)
	env := &doctorEnv{
		wrapperDir: "/fixture",
		readFile: func(path string) ([]byte, error) {
			if path != "/fixture/plk-contained-launch" {
				return nil, os.ErrNotExist
			}
			return []byte(wrapper), nil
		},
		runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
			if len(args) == 4 && args[2] == "--property=BindReadOnlyPaths" {
				return binds, 0, nil
			}
			return strings.Join(runtimeSocketTemporaryFileSystems(), " "), 0, nil
		},
	}
	if got := probeDoctorRuntimeSockets(t.Context(), env); got.status != statusPass {
		t.Fatalf("rendered forwarder binds = %+v, want pass", got)
	}
	// The notify bind is admitted alongside the doorway bind, not instead of it.
	binds = notifyBindShow()
	if got := probeDoctorRuntimeSockets(t.Context(), env); got.status != statusFail {
		t.Fatalf("notify bind without doorway bind = %+v, want fail", got)
	}
	// A different extra bind is still refused.
	binds = renderedBindShow(t, unit) + " /run/user:/run/user:rbind"
	if got := probeDoctorRuntimeSockets(t.Context(), env); got.status != statusFail {
		t.Fatalf("extra runtime bind = %+v, want fail", got)
	}
}
