// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	googleEditorSuffix      = "/edit"
	googlePathEntropyReason = "high entropy path segment"
	googleDocsTestOrigin    = "https://docs.google.com"
	googleDriveTestOrigin   = "https://drive.google.com"
	googleDocumentTestRoute = googleDocsTestOrigin + "/document/d/"
	googleFormFixtureID     = "AbCd0123EfGh4567IjKl89MnOpQrStUvWxYzABCDEFghijklMNOPQRstu"
	googleTrailingFixture   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

func TestShippedGoogleEditorPathEntropy(t *testing.T) {
	t.Parallel()
	s := pathExclusionScanner(t, config.ShippedPathEntropyExclusions()...)
	t.Cleanup(s.Close)
	googleEditorFixtureID, googleDriveFixtureID := highEntropyID[:44], highEntropyID[:33]
	for _, id := range []string{googleEditorFixtureID, googleDriveFixtureID, googleFormFixtureID, "2PACX-" + googleFormFixtureID, googleTrailingFixture} {
		got, blocked := s.pathEntropy("/" + id)
		t.Logf("fixture length %d, ordinary path entropy %.2f", len(id), got)
		if !blocked {
			t.Fatal("fixture must exceed the balanced path-entropy threshold")
		}
	}

	for _, tt := range []struct {
		name        string
		target      string
		blockReason string
	}{
		{"document", googleDocumentTestRoute + googleEditorFixtureID + googleEditorSuffix, ""},
		{"spreadsheet", googleDocsTestOrigin + "/spreadsheets/d/" + googleEditorFixtureID + googleEditorSuffix, ""},
		{"presentation", googleDocsTestOrigin + "/presentation/d/" + googleEditorFixtureID + googleEditorSuffix, ""},
		{"drive file", googleDriveTestOrigin + "/file/d/" + googleDriveFixtureID + "/view", ""},
		{"form response", googleDocsTestOrigin + "/forms/d/e/" + googleFormFixtureID + "/viewform", ""},
		{"published document", googleDocumentTestRoute + "e/2PACX-" + googleFormFixtureID + "/pub", ""},
		{"published spreadsheet", googleDocsTestOrigin + "/spreadsheets/d/e/2PACX-" + googleFormFixtureID + "/pub", ""},
		{"published presentation", googleDocsTestOrigin + "/presentation/d/e/2PACX-" + googleFormFixtureID + "/pub", ""},
		{"document account zero", googleDocsTestOrigin + "/document/u/0/d/" + googleEditorFixtureID + googleEditorSuffix, ""},
		{"spreadsheet account", googleDocsTestOrigin + "/spreadsheets/u/12/d/" + googleEditorFixtureID + googleEditorSuffix, ""},
		{"presentation account", googleDocsTestOrigin + "/presentation/u/12/d/" + googleEditorFixtureID + googleEditorSuffix, ""},
		{"drive account", googleDriveTestOrigin + "/file/u/12/d/" + googleDriveFixtureID + "/view", ""},
		{"form account", googleDocsTestOrigin + "/forms/u/12/d/e/" + googleFormFixtureID + "/viewform", ""},
		{"published account", googleDocsTestOrigin + "/document/u/12/d/e/2PACX-" + googleFormFixtureID + "/pub", ""},
		{"id is final segment", googleDocumentTestRoute + googleEditorFixtureID, ""},
		{"escaped id", googleDocumentTestRoute + "%70" + googleEditorFixtureID[1:] + googleEditorSuffix, ""},
		{"trailing segment", googleDocumentTestRoute + googleEditorFixtureID + "/" + googleTrailingFixture, googlePathEntropyReason},
		{"published trailing segment", googleDocumentTestRoute + "e/2PACX-" + googleFormFixtureID + "/" + googleTrailingFixture, googlePathEntropyReason},
		{"form trailing segment", googleDocsTestOrigin + "/forms/d/e/" + googleFormFixtureID + "/" + googleTrailingFixture, googlePathEntropyReason},
		{"segment before slot", googleDocsTestOrigin + "/document/" + googleTrailingFixture + "/d/" + googleEditorFixtureID + googleEditorSuffix, googlePathEntropyReason},
		{"second ID", googleDocumentTestRoute + googleEditorFixtureID + "/" + highEntropyID + googleEditorSuffix, googlePathEntropyReason},
		{"repeated ID", googleDocumentTestRoute + googleEditorFixtureID + "/" + googleEditorFixtureID + googleEditorSuffix, googlePathEntropyReason},
		{"empty ID", googleDocumentTestRoute + "/" + googleTrailingFixture, googlePathEntropyReason},
		{"empty published ID", googleDocumentTestRoute + "e//" + googleTrailingFixture, googlePathEntropyReason},
		{"encoded slash in slot", googleDocumentTestRoute + googleEditorFixtureID + "%2F" + googleTrailingFixture, googlePathEntropyReason},
		{"doubly encoded slash in slot", googleDocumentTestRoute + googleEditorFixtureID + "%252F" + googleTrailingFixture, googlePathEntropyReason},
		{"encoded backslash in slot", googleDocumentTestRoute + googleEditorFixtureID + "%5C" + googleTrailingFixture, googlePathEntropyReason},
		{"encoded route separator", googleDocsTestOrigin + "/document%2Fd/" + googleEditorFixtureID, googlePathEntropyReason},
		{"missing account index", googleDocsTestOrigin + "/document/u//d/" + googleEditorFixtureID, googlePathEntropyReason},
		{"account without delimiters", googleDocsTestOrigin + "/document/u/" + googleEditorFixtureID, googlePathEntropyReason},
		{"nonnumeric account index", googleDocsTestOrigin + "/document/u/12a/d/" + googleEditorFixtureID, googlePathEntropyReason},
		{"missing document route after account", googleDocsTestOrigin + "/document/u/12/" + googleEditorFixtureID, googlePathEntropyReason},
		{"other host", "https://docs.vendor.example/document/d/" + googleEditorFixtureID + googleEditorSuffix, googlePathEntropyReason},
		{"other port", googleDocsTestOrigin + ":8443/document/d/" + googleEditorFixtureID + googleEditorSuffix, googlePathEntropyReason},
		{"explicit default port", googleDocsTestOrigin + ":443/document/d/" + googleEditorFixtureID + googleEditorSuffix, ""},
		{"query value", googleDocumentTestRoute + googleEditorFixtureID + "/edit?value=" + googleTrailingFixture, "high entropy query param"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := s.Scan(t.Context(), tt.target)
			t.Logf("allowed=%t reason=%q", got.Allowed, got.Reason)
			if tt.blockReason == "" {
				if !got.Allowed {
					t.Errorf("expected allow, got %q", got.Reason)
				}
			} else if got.Allowed || got.Scanner != ScannerEntropy || !strings.Contains(got.Reason, tt.blockReason) {
				t.Errorf("expected entropy block %q, got allowed=%t reason=%q scanner=%q", tt.blockReason, got.Allowed, got.Reason, got.Scanner)
			}
		})
	}
}

func TestPathEntropyExclusionBuilderDropsInvalidGoogleSlot(t *testing.T) {
	t.Parallel()
	entry := config.ShippedPathEntropyExclusions()[0]
	entry.Host = "docs.vendor.example"
	if got := buildPathEntropyExclusions([]config.PathEntropyExclusion{entry}); len(got) != 0 {
		t.Fatalf("compiled an ID slot for an invalid host: %+v", got)
	}
	if (&Scanner{}).isPathEntropyExcluded(nil) {
		t.Fatal("matched an absent URL")
	}
}
