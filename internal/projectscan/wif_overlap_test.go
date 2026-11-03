// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package projectscan

import "testing"

func TestProjectWIFOverlappingCandidates(t *testing.T) {
	patterns, err := compileDLPPatterns()
	if err != nil {
		t.Fatal(err)
	}
	key := "K" + "KwdMAjGmer" + "Yanjeui5SHS7Jkmp" + "ZvVipYvB2LJGU1ZxJwYvP98617"
	for _, p := range patterns {
		if p.name == "Bitcoin WIF Private Key" {
			if !p.matches(key) {
				t.Fatal("overlapping WIF not detected")
			}
			return
		}
	}
	t.Fatal("WIF pattern missing")
}
