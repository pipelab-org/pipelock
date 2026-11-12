// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

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
