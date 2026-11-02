// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// WebSocketCredentialAudienceSurface earns a structured carrier only from a
// complete client text frame. Callers must supply their verified upstream URL,
// never a URL inside the frame. Control, binary, server and cross-message views
// must keep the ordinary websocket_frame surface. The returned scan view removes
// only the authenticated value for subsequent cross-message checks; it must
// never replace the forwarded frame.
//
// Discord publishes Identify (op 2) and Resume (op 6) with a string d.token:
// https://docs.discord.com/developers/events/gateway-events#identify
// https://docs.discord.com/developers/events/gateway-events#resume
func (s *Scanner) WebSocketCredentialAudienceSurface(ctx context.Context, frame []byte, target string) (surface string, scanView []byte, invalid bool) {
	const fallback = "websocket_frame"
	host, ok := canonicalCredentialAudienceDestination(target)
	parsed, err := url.Parse(target)
	if !ok || host != "gateway.discord.gg" || err != nil || parsed.Scheme != "wss" || ctx.Err() != nil {
		return fallback, nil, false
	}
	if !json.Valid(frame) {
		return fallback, nil, true
	}
	if err := jsonscan.RejectDuplicateKeys(frame); err != nil {
		return fallback, nil, true
	}
	var envelope, data map[string]json.RawMessage
	var op int
	var credential string
	if json.Unmarshal(frame, &envelope) != nil || !jsonField(envelope, "op", &op) {
		return fallback, nil, true
	}
	if op != 2 && op != 6 {
		return fallback, nil, false
	}
	if !jsonField(envelope, "d", &data) || !jsonField(data, "token", &credential) || credential == "" {
		return fallback, nil, true
	}
	var qualified *compiledPattern
	for _, pattern := range s.dlpPatterns {
		if pattern.credentialAudienceCarrierMask&config.CredentialAudienceCarrierDiscordGateway == 0 {
			continue
		}
		start, end, matched := pattern.matchSpan(credential)
		if !matched || start != 0 || end != len(credential) {
			continue
		}
		if _, allowed := s.credentialAudienceAllows(pattern, target, credentialAudienceDiscordGatewaySurface); allowed {
			qualified = pattern
			break
		}
	}
	if qualified == nil {
		return fallback, nil, false
	}
	// Removing only the authenticated field leaves keys, presence, activities,
	// and every other value inspectable. Another match of the authenticated
	// credential's pattern, including an encoded or split copy, prevents the
	// carrier. Other patterns retain their ordinary DLP and operator policy.
	rawCredential := data["token"]
	delete(data, "token")
	remainingData, err := json.Marshal(data)
	if err != nil {
		return fallback, nil, false
	}
	envelope["d"] = remainingData
	remaining, err := json.Marshal(envelope)
	if err != nil {
		return fallback, nil, false
	}
	extracted := extract.AllStringsFromJSONResult(remaining)
	if extracted.Truncated {
		return fallback, nil, false
	}
	for _, view := range append(extracted.Strings, string(remaining), strings.Join(extracted.Strings, "")) {
		for _, match := range s.ScanTextForDLPQuiet(ctx, view).Matches {
			if match.PatternName == qualified.name {
				return fallback, nil, false
			}
		}
		if ctx.Err() != nil {
			return fallback, nil, false
		}
	}
	// The original raw JSON value occurs once: a second copy elsewhere would
	// make the replacement ambiguous. Preserve every other byte and its order
	// in the cross-message scan view; only the authenticated value disappears.
	if bytes.Count(frame, rawCredential) != 1 {
		return fallback, nil, false
	}
	return credentialAudienceDiscordGatewaySurface, bytes.Replace(frame, rawCredential, []byte(`""`), 1), false
}
