// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// An unreadable relative scan root is reported at the root itself, never at a
// doubled path such as service/service.
func TestAuditCmd_SARIFUnreadableRelativeRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode 000 directories")
	}
	root := t.TempDir()
	sub := filepath.Join(root, "service")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Chmod(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Chmod(sub, 0o700) })

	t.Chdir(root)

	cmd := testRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit", "service", "--format", "sarif"})
	_ = cmd.Execute()

	var parsed struct {
		Runs []struct {
			Results []struct {
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	start := strings.Index(buf.String(), "{")
	if start < 0 {
		t.Fatalf("no SARIF output: %s", buf.String())
	}
	if err := json.NewDecoder(strings.NewReader(buf.String()[start:])).Decode(&parsed); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, buf.String())
	}
	found := false
	for _, r := range parsed.Runs[0].Results {
		if !strings.Contains(r.Message.Text, "for secrets (unreadable)") {
			continue
		}
		found = true
		for _, loc := range r.Locations {
			if uri := loc.PhysicalLocation.ArtifactLocation.URI; uri != "service" {
				t.Errorf("unreadable root URI = %q, want %q", uri, "service")
			}
		}
	}
	if !found {
		t.Fatalf("no unreadable-root warning in SARIF:\n%s", buf.String())
	}
}
