// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
	risksession "github.com/luckyPipewrench/pipelock/internal/session"
)

func TestRenderHostileFindingKinds(t *testing.T) {
	for _, tc := range []struct{ name, raw, want string }{
		{"wording", `{"prompt_hit":true,"finding_kinds":["prompt_injection_wording"]}`, "hostile because of prompt-injection wording only"},
		{"mixed", `{"prompt_hit":true,"finding_kinds":["prompt_injection_wording","dlp"]}`, "hostile because of DLP, prompt-injection wording"},
		{"legacy", `{"prompt_hit":true}`, "cause not recorded (older state or aggregate finding)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var risk risksession.SessionRisk
			if err := json.Unmarshal([]byte(tc.raw), &risk); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := renderExplanation(&out, proxy.SessionExplanation{Key: "client", FindingKinds: risk.FindingKinds}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("explain omitted cause: %s", out.String())
			}
			out.Reset()
			if err := renderDetail(&out, proxy.SessionDetail{SessionSnapshot: proxy.SessionSnapshot{Key: "client", FindingKinds: risk.FindingKinds}}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("inspect omitted cause: %s", out.String())
			}
		})
	}
}

// The CLI decodes admin API DTOs, not SessionRisk JSON. A proxy that predates
// cause attribution reports a hostile taint level without finding_kinds.
func TestRenderDetailTaintCauseFromAPIShapes(t *testing.T) {
	for _, tc := range []struct{ name, raw, want string }{
		{"older proxy hostile", `{"key":"client","taint_level":"external_hostile","contaminated":true}`, "  taint_cause:      hostile: cause not recorded (older state or aggregate finding)\n"},
		{"current proxy wording", `{"key":"client","taint_level":"external_hostile","contaminated":true,"finding_kinds":["prompt_injection_wording"]}`, "  taint_cause:      hostile because of prompt-injection wording only\n"},
		{"current proxy unknown kind", `{"key":"client","taint_level":"external_hostile","finding_kinds":["\u001b[2Jfuture"]}`, "  taint_cause:      hostile: cause not recorded (older state or aggregate finding)\n"},
		{"untrusted", `{"key":"client","taint_level":"external_untrusted","contaminated":true}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d proxy.SessionDetail
			if err := json.Unmarshal([]byte(tc.raw), &d); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := renderDetail(&out, d); err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if strings.Contains(out.String(), "taint_cause") {
					t.Fatalf("non-hostile session reported a hostile cause: %s", out.String())
				}
				return
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("detail cause = %q, want line %q", out.String(), tc.want)
			}
		})
	}
	var out bytes.Buffer
	if err := renderExplanation(&out, proxy.SessionExplanation{Key: "client", FindingKinds: []risksession.HostileFindingKind{risksession.FindingDLP}}); err != nil {
		t.Fatal(err)
	}
	tier, cause := -1, -1
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "  tier:") {
			tier = len(line) - len(strings.TrimLeft(strings.TrimPrefix(line, "  tier:"), " "))
		}
		if strings.HasPrefix(line, "  taint_cause:") {
			cause = len(line) - len(strings.TrimLeft(strings.TrimPrefix(line, "  taint_cause:"), " "))
		}
	}
	if tier < 0 || tier != cause {
		t.Fatalf("explanation cause column %d does not match tier column %d:\n%s", cause, tier, out.String())
	}
}
