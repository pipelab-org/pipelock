// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testFileDeleteRule       = "Destructive File Delete"
	testPermissionChangeRule = "Recursive Permission Change"
)

// Read-only utilities given literal data print or search text. A command named
// inside that text does not run, so the command rules do not match it.
func TestShellDataProofCoversCommandRules(t *testing.T) {
	pc := defaultConfigWithIncomplete(t, config.ActionBlock)
	for _, command := range []string{
		"grep -R 'git push --force' docs/ || true",
		"grep -R 'git rm --force x' docs/",
		"grep -R 'rm -rf /tmp/x' docs/",
		"echo 'git push --force'",
		"grep -rn 'chmod -R 777' scripts/",
	} {
		t.Run(command, func(t *testing.T) {
			if p := proveShellRules(command); p == nil || p.data == nil {
				t.Fatal("literal-data proof did not hold")
			}
			v := pc.CheckShellCommand(command, nil)
			for _, rule := range []string{testFileDeleteRule, testPermissionChangeRule} {
				if slices.Contains(v.Rules, rule) {
					t.Fatalf("%s matched printed text: %+v", rule, v)
				}
			}
		})
	}
}

// Anything that can run the text, or a real command beside it, keeps the
// whole-script match.
func TestShellDataProofKeepsRunnableCommandRules(t *testing.T) {
	pc := defaultConfigWithIncomplete(t, config.ActionBlock)
	for _, tt := range []struct{ command, rule string }{
		{"rm -rf ~/work", testFileDeleteRule},
		{"grep -R x docs/; rm -rf ~/work", testFileDeleteRule},
		{"echo done && rm -rf ~/work", testFileDeleteRule},
		{"echo 'rm -rf ~/work' | sh", testFileDeleteRule},
		{"grep x $(rm -rf ~/work)", testFileDeleteRule},
		{"echo `rm -rf ~/work`", testFileDeleteRule},
		{"grep() { rm -rf ~/work; }\ngrep x docs/", testFileDeleteRule},
		{"eval \"$(echo rm -rf ~/work)\"", testFileDeleteRule},
		{"echo ~/work | xargs rm -rf", testFileDeleteRule},
		{"PATH=/tmp/e:$PATH grep 'rm -rf' .", testFileDeleteRule},
		{"/tmp/e/grep 'rm -rf' .", testFileDeleteRule},
		{". ./x.sh; echo 'rm -rf'", testFileDeleteRule},
		{"git rm --force secrets.txt", testFileDeleteRule},
		{"chmod -R 777 ~/work", testPermissionChangeRule},
		{"echo ok; chmod -R 777 ~/work", testPermissionChangeRule},
	} {
		t.Run(tt.command, func(t *testing.T) {
			if v := pc.CheckShellCommand(tt.command, nil); !slices.Contains(v.Rules, tt.rule) {
				t.Fatalf("%s lost its match: %+v", tt.rule, v)
			}
		})
	}
}
