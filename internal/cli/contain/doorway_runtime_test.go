// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDoorwayRemovalClearsRuntimeEnablement(t *testing.T) {
	for _, publishedOnly := range []bool{true, false} {
		for _, backup := range []bool{false, true} {
			name := map[bool]string{true: "published", false: "namespace"}[publishedOnly]
			if backup {
				name += "/restore-backup"
			}
			t.Run(name, func(t *testing.T) {
				env, _, _ := newFakeEnv(t)
				service := loopbackTestService(49200)
				putInstallRefusalInventories(t, env, []config.ContainmentLoopbackService{service})
				loopback := loopbackForwarderUnitBase(service.Host, service.Port) + ".socket"
				publication := "pipelock-published-viewer.socket"
				enabled := map[string]bool{loopback: true, strings.TrimSuffix(loopback, ".socket") + "-netns.service": true, publication: true, filepath.Base(env.proxyForwarderSocketPath): true, filepath.Base(env.networkNamespaceUnitPath): true}
				unitDir := filepath.Dir(env.proxyForwarderSocketPath)
				original := func(unit string) string {
					if strings.HasSuffix(unit, ".socket") {
						return "[Socket]\nListenStream=127.0.0.1:49200\n"
					}
					return "[Service]\nType=oneshot\nExecStart=/usr/bin/true\n"
				}
				if backup {
					for unit := range enabled {
						if err := os.WriteFile(filepath.Join(unitDir, unit+".bak"), []byte(original(unit)), 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
				env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
					if args[0] == "disable" && slices.Contains(args, "--runtime") {
						unit := args[len(args)-1]
						if _, tracked := enabled[unit]; tracked {
							enabled[unit] = false
						}
					}
					if args[0] == "show" {
						return "inactive\n", 0, nil
					}
					return "", 0, nil
				}
				var err error
				if publishedOnly {
					err = removePublishedServices(t.Context(), env)
				} else {
					err = actionRemoveNetworkNamespace().undo(t.Context(), env)
				}
				if err != nil {
					t.Fatal(err)
				}
				for unit, armed := range enabled {
					wantArmed := publishedOnly && unit != publication
					if armed != wantArmed {
						t.Fatalf("unit %s runtime enabled=%v, want %v", unit, armed, wantArmed)
					}
					if backup && !wantArmed {
						body, err := os.ReadFile(filepath.Clean(filepath.Join(unitDir, unit)))
						if err != nil || string(body) != original(unit) {
							t.Fatalf("original unit was not restored: %s %q %v", unit, body, err)
						}
					}
				}
			})
		}
	}
}

func assertRuntimeDoorwaysDisabled(t *testing.T, runner *fakeRunner, units []string) {
	t.Helper()
	for _, unit := range units {
		if strings.HasSuffix(unit, ".socket") || strings.HasSuffix(unit, "-netns.service") {
			if !runnerCalled(runner, "disable --runtime --now "+unit) {
				t.Errorf("revoked doorway %s did not clear runtime enablement", unit)
			}
		}
	}
}

func TestDoorwayRevocationRemovesRuntimeEnablement(t *testing.T) {
	for _, kind := range []string{"loopback", "published"} {
		t.Run(kind, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			unit := "pipelock-published-example.socket"
			targets := []string{unit}
			closeDoorways := closePublishedDoorways
			if kind == "loopback" {
				unit = loopbackForwarderUnitBase("127.0.0.1", 49200)
				targets = []string{unit + "-netns.service", unit + ".socket"}
				closeDoorways = closeLoopbackDoorways
			}
			enabled := map[string]bool{}
			for _, target := range targets {
				enabled[target] = true
			}
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if name != "systemctl" || ctx.Err() != nil {
					t.Fatalf("invalid cleanup command %s %v: %v", name, args, ctx.Err())
				}
				if args[0] == "disable" && slices.Contains(args, "--runtime") {
					enabled[args[len(args)-1]] = false
				}
				if args[0] == "show" {
					return "inactive\n", 0, nil
				}
				return "", 0, nil
			}
			if err := closeDoorways(t.Context(), env, []string{unit}); err != nil {
				t.Fatal(err)
			}
			for _, target := range targets {
				if enabled[target] {
					t.Fatalf("revoked doorway %s remains enabled at runtime", target)
				}
			}
		})
	}
}

func TestDoorwayRevocationAttemptsBothEnablementStores(t *testing.T) {
	for _, failed := range []string{"persistent", "runtime"} {
		t.Run(failed, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			failure := errors.New("disable failed")
			var calls []string
			env.runCmd = func(ctx context.Context, _ string, args ...string) (string, int, error) {
				if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
					t.Fatal("revocation lost its independent command deadline")
				}
				store := "persistent"
				if slices.Contains(args, "--runtime") {
					store = "runtime"
				}
				calls = append(calls, store)
				if store == failed {
					return "", 1, failure
				}
				return "", 0, nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			err := runRevocationSystemctl(ctx, env, "disable", "--now", "example.socket")
			if !errors.Is(err, failure) || strings.Join(calls, ",") != "persistent,runtime" {
				t.Fatalf("error=%v calls=%v", err, calls)
			}
		})
	}
}
