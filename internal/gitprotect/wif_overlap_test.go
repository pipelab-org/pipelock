// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package gitprotect

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDiffWIFOverlappingCandidates(t *testing.T) {
	key := "K" + "KwdMAjGmer" + "Yanjeui5SHS7Jkmp" + "ZvVipYvB2LJGU1ZxJwYvP98617"
	for _, p := range CompileDLPPatterns(config.DefaultDLPPatterns()) {
		if p.Name == "Bitcoin WIF Private Key" {
			if !p.regexMatches(key) {
				t.Fatal("overlapping WIF not detected")
			}
			return
		}
	}
	t.Fatal("WIF pattern missing")
}
