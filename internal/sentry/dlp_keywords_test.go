// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package plsentry

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordsScrubberRemainsConservative(t *testing.T) {
	scrub := NewScrubber([]config.DLPPattern{{Name: "account", Regex: `[0-9]{16}`, Keywords: []string{"account"}}}, nil)
	if strings.Contains(scrub.ScrubString("3333333333333333"), "3333333333333333") {
		t.Fatal("keyword tuning exposed unlabeled match in telemetry")
	}
}
