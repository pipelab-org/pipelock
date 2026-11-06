// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/spf13/cobra"
)

func TestDLPKeywordsExplain(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "account identifier", Regex: `[0-9]{16}`, Keywords: []string{"account"}, KeywordWindow: new(30)}}
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	report, err := buildExplainReport(cmd, cfg, "configuration.yaml", "https://api.vendor.example/?value=3333333333333333")
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(report.Notes, " ")
	for _, want := range []string{"dlp.patterns[0]", "30 Unicode scalar values", "either side", "source or producing decoded context", "missing labels"} {
		if !strings.Contains(notes, want) {
			t.Errorf("explain missing %q: %s", want, notes)
		}
	}
	if strings.Contains(notes, "3333333333333333") {
		t.Fatal("explain leaked candidate into keyword diagnostics")
	}
}
