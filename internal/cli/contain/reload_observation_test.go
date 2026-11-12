// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestReloadNFTRulesRefusesEmptyObservation(t *testing.T) {
	t.Parallel()
	rules := renderNFTRules(1000, 967, 966, 8888, defaultNFTTable, defaultNFTChain)
	wrote, applied := false, false
	env := &nftReloadEnv{
		nftPath: "nft", rulesPath: "/managed/50-pipelock-containment.nft", table: defaultNFTTable, chain: defaultNFTChain,
		readFile:   func(string) ([]byte, error) { return []byte(rules), nil },
		writeFile:  func(string, []byte, os.FileMode) error { wrote = true; return nil },
		removeFile: func(string) error { return nil },
		runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
			if len(args) == 2 && args[0] == "-f" {
				applied = true
			}
			return "", 0, nil
		},
	}
	err := reloadNFTForTest(t, context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "empty observation") {
		t.Fatalf("error=%v, want empty-observation refusal", err)
	}
	if wrote || applied {
		t.Fatalf("unknown observation changed nft state: wrote=%v applied=%v", wrote, applied)
	}
}

func TestObserveNFTManagedChain(t *testing.T) {
	t.Parallel()
	healthy := nftListingForTest(renderNFTRules(1000, 967, 966, 8888, defaultNFTTable, defaultNFTChain))
	for _, tc := range []struct {
		name, output, wantError string
		code                    int
		cause                   error
		absent                  bool
	}{
		{"present", healthy, "", 0, nil, false},
		{"missing file", "Error: No such file or directory", "", 1, nil, true},
		{"missing object", "table does not exist", "", 1, nil, true},
		{"empty success", "", "empty observation", 0, nil, false},
		{"whitespace success", " \n\t", "empty observation", 0, nil, false},
		{"empty failure", "", "exit=1", 1, nil, false},
		{"permission failure", "Operation not permitted", "exit=1", 1, nil, false},
		{"launch failure", "", "list nft managed chain", -1, os.ErrPermission, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(_ context.Context, name string, args ...string) (string, int, error) {
				if name != "nft" || strings.Join(args, " ") != "-n -a list chain inet "+defaultNFTTable+" "+defaultNFTChain {
					t.Fatalf("unexpected nft observation: %s %v", name, args)
				}
				return tc.output, tc.code, tc.cause
			}
			got, err := observeNFTManagedChain(t.Context(), run, "nft", defaultNFTTable, defaultNFTChain)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) || got != "" {
					t.Fatalf("got=%q error=%v", got, err)
				}
				if tc.cause != nil && !errors.Is(err, tc.cause) {
					t.Fatalf("lost cause: %v", err)
				}
			} else if err != nil || (tc.absent && got != "") || (!tc.absent && got != tc.output) {
				t.Fatalf("got=%q error=%v", got, err)
			}
		})
	}
}
