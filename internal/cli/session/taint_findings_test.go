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
