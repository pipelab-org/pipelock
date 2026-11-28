// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestRunExplain_HappyPathText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	line := `{"id":"evt-1","class":"tool_ignores_proxy","process":"node","pid":123,"uid":987,"dest":"203.0.113.10","port":443,"protocol":"tcp"}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write events: %v", err)
	}

	var out bytes.Buffer
	err := runExplain(&out, containExplainOpts{eventsPath: path, format: "text"}, "evt-1")
	if err != nil {
		t.Fatalf("runExplain: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"event: evt-1",
		"class: tool_ignores_proxy",
		"process: node pid=123",
		"uid: 987",
		"destination: 203.0.113.10:443",
		"tool ignores proxy settings",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunExplain_JSONIncludesDefaultRemediation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	line := `{"id":"evt-2","class":"direct_dns_blocked","dest":"198.51.100.53","port":53}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write events: %v", err)
	}

	var out bytes.Buffer
	err := runExplain(&out, containExplainOpts{eventsPath: path, format: "json"}, "evt-2")
	if err != nil {
		t.Fatalf("runExplain: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, `"remediation": "direct DNS is blocked`) {
		t.Fatalf("json output missing remediation:\n%s", got)
	}
}

func TestRunExplain_PrintsExplicitZeroMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	line := `{"id":"evt-root","class":"not_routing_through_pipelock","process":"init","pid":0,"uid":0,"dest":"127.0.0.1","port":0}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write events: %v", err)
	}

	var out bytes.Buffer
	err := runExplain(&out, containExplainOpts{eventsPath: path, format: "text"}, "evt-root")
	if err != nil {
		t.Fatalf("runExplain: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"process: init pid=0",
		"uid: 0",
		"destination: 127.0.0.1:0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunExplain_RefusesReceiptProfiles(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, _, path string) {
		for _, id := range []string{"", "evt-1"} {
			var out bytes.Buffer
			err := runExplain(&out, containExplainOpts{eventsPath: path, format: "text"}, id)
			if err == nil || !strings.Contains(err.Error(), "pipelock verify-receipt") {
				t.Fatalf("runExplain(id=%q, path=%s): err=%v, out=%q; want receipt verifier guidance", id, path, err, out.String())
			}
		}
	})

	t.Run("renamed v3 content with leading whitespace", func(t *testing.T) {
		v3File, _ := testreceipt.V3(t, t.TempDir(), false)
		raw, err := os.ReadFile(filepath.Clean(v3File))
		if err != nil {
			t.Fatal(err)
		}
		renamed := filepath.Join(t.TempDir(), "egress-events.jsonl")
		if err := os.WriteFile(renamed, append([]byte("\n  "), raw...), 0o600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err = runExplain(&out, containExplainOpts{eventsPath: renamed, format: "text"}, "")
		if err == nil || !strings.Contains(err.Error(), "pipelock verify-receipt") {
			t.Fatalf("renamed v3 content: err=%v, out=%q; want receipt verifier guidance", err, out.String())
		}
	})

	t.Run("oversized line before v3 record", func(t *testing.T) {
		v3File, _ := testreceipt.V3(t, t.TempDir(), false)
		raw, err := os.ReadFile(filepath.Clean(v3File))
		if err != nil {
			t.Fatal(err)
		}
		oversized := filepath.Join(t.TempDir(), "egress-events.jsonl")
		data := append([]byte(strings.Repeat("x", 128<<10)+"\n"), raw...)
		if err := os.WriteFile(oversized, data, 0o600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err = runExplain(&out, containExplainOpts{eventsPath: oversized, format: "text"}, "evt-1")
		if err == nil || !strings.Contains(err.Error(), "pipelock verify-receipt") {
			t.Fatalf("oversized line: err=%v, out=%q; want receipt verifier guidance", err, out.String())
		}
	})
}

func TestFindEgressBlockEventRefusesLaterReceipt(t *testing.T) {
	file := filepath.Join(t.TempDir(), "events.jsonl")
	data := []byte("{\"id\":\"event-1\"}\n" + evidencename.ReceiptProfilePrefix + "v3\"}\n")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := findEgressBlockEvent(file, "event-1")
	if !errors.Is(err, evidencename.ErrReceiptProfile) {
		t.Fatalf("findEgressBlockEvent() error = %v, want receipt refusal", err)
	}
}

func TestFindEgressBlockEventKeepsFirstMatch(t *testing.T) {
	file := filepath.Join(t.TempDir(), "events.jsonl")
	data := []byte("{\"id\":\"event-1\",\"class\":\"first\"}\n{\"id\":\"event-1\",\"class\":\"second\"}\n")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	event, err := findEgressBlockEvent(file, "event-1")
	if err != nil || event.Class != "first" {
		t.Fatalf("event = %+v, error = %v", event, err)
	}
}
