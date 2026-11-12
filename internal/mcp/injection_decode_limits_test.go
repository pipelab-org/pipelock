// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestInjectionDecodeLimitsMcp(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.PromptInjectionDetection = &config.PromptInjectionDetection{Action: config.ActionWarn}
	sc := scanner.MustNew(cfg)
	text := "ordinary neutral text"
	for range 6 {
		text = base64.StdEncoding.EncodeToString([]byte(text))
	}
	encoded, err := json.Marshal(text)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"text":` + string(encoded) + `}}}`)
	input := ScanRequest(t.Context(), request, sc, config.ActionWarn, config.ActionWarn)
	if input.Clean || input.Action != config.ActionBlock || !strings.Contains(input.Error, "injection inspection incomplete") {
		t.Errorf("outbound: %+v", input)
	}
	warnings := 0
	sc.SetDLPWarnHook(func(_ context.Context, name, _ string) {
		if name == scanner.PartialEncodedContentPattern {
			warnings++
		}
	})
	response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + string(encoded) + `}]}}`)
	output := ScanResponse(response, sc)
	if !output.Clean || output.Error != "" || output.Assessment.Status != scanner.AssessmentIncomplete || warnings == 0 {
		t.Errorf("inbound: %+v warnings=%d", output, warnings)
	}
}
