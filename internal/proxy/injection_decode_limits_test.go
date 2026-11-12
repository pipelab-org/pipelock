// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestInjectionDecodeLimitsProxy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.PromptInjectionDetection = &config.PromptInjectionDetection{Action: config.ActionWarn}
	sc := scanner.MustNew(cfg)
	text := "ordinary neutral text"
	for range 6 {
		text = base64.StdEncoding.EncodeToString([]byte(text))
	}
	encoded, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		t.Fatal(err)
	}
	_, r := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(string(encoded)), ContentType: "application/json", MaxBytes: 1 << 20, Scanner: sc, Action: config.ActionWarn, Target: "https://api.vendor.example/upload"})
	if r.Clean || r.Action != config.ActionBlock || !strings.Contains(r.ScanError, "injection inspection incomplete") {
		t.Errorf("outbound: %+v", r)
	}
	// The same representation is delivered inbound with explicit warning evidence.
	warnings := 0
	sc.SetDLPWarnHook(func(_ context.Context, name, _ string) {
		if name == scanner.PartialEncodedContentPattern {
			warnings++
		}
	})
	inbound := sc.ScanResponseBodyWithSuppress(t.Context(), []byte(text), "", nil)
	if !inbound.Clean || inbound.Failed() || inbound.Assessment.Status != scanner.AssessmentIncomplete || warnings == 0 {
		t.Errorf("inbound: %+v warnings=%d", inbound, warnings)
	}
}
