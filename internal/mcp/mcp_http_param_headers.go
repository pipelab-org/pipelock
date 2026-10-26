// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

const (
	mcpParamHeaderPrefix = "mcp-param-"
	maxMCPMirrorInteger  = int64(9007199254740991)
)

// mcpToolContractRejected reports a tools/call naming a tool whose listed
// x-mcp-header contract was invalid. The caller cannot fix that by changing
// headers, so the refusal says the definition was rejected.
func mcpToolContractRejected(frame MCPFrame, baseline *tools.ToolBaseline) bool {
	return frame.Method == methodToolsCall && frame.RoutingNameErr == nil && frame.RoutingName != "" &&
		baseline.HeaderContract(frame.RoutingName).State == tools.HeaderContractInvalid
}

// validateMCPParamHeaders verifies every recognized 2026-07-28 mirrored tool
// parameter against the exact property path in the accepted tools/list schema.
// Unknown headers remain intermediary data and are forwarded after scanning, as
// the protocol requires. A known schema is strict in both directions: a body
// value requires its header, and a recognized header requires its body value.
func validateMCPParamHeaders(headers map[string][]string, frame MCPFrame, baseline *tools.ToolBaseline) bool {
	if frame.RoutingNameErr != nil {
		return false
	}
	if frame.Method != methodToolsCall || baseline == nil || frame.RoutingName == "" {
		return true
	}
	contract := baseline.HeaderContract(frame.RoutingName)
	if contract.State == tools.HeaderContractInvalid {
		return false
	}
	if contract.State == tools.HeaderContractUnknown {
		return true
	}
	paramHeaders := make(map[string][]string)
	for name, values := range headers {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, mcpParamHeaderPrefix) {
			paramHeaders[strings.TrimPrefix(lower, mcpParamHeaderPrefix)] = values
		}
	}
	for lowerName, binding := range contract.Bindings {
		raw, present, ok := argumentAtPath(frame.Args, binding.Path)
		if !ok {
			return false
		}
		values := paramHeaders[lowerName]
		if !present || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			if len(values) != 0 {
				return false
			}
			continue
		}
		if len(values) != 1 {
			return false
		}
		decoded, ok := decodeMCPHeaderValue(values[0])
		if !ok || !mcpParamValueMatches(decoded, raw, binding.Type) {
			return false
		}
	}
	return true
}

func argumentAtPath(arguments json.RawMessage, path []string) (json.RawMessage, bool, bool) {
	if len(arguments) == 0 {
		return nil, false, true
	}
	current := arguments
	for _, part := range path {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(current, &object); err != nil {
			return nil, false, false
		}
		next, exists := object[part]
		if !exists {
			return nil, false, true
		}
		current = next
	}
	return current, true, true
}

func decodeMCPHeaderValue(value string) (string, bool) {
	decoded, ok := decodeMCPWireValue(value)
	if !ok {
		return "", false
	}
	if strings.HasPrefix(value, "=?base64?") {
		return decoded, true
	}
	if decoded == "" || strings.TrimSpace(decoded) != decoded {
		return "", false
	}
	for i := range len(decoded) {
		if (decoded[i] < 0x20 || decoded[i] > 0x7e) && decoded[i] != '\t' {
			return "", false
		}
	}
	return decoded, true
}

func mcpParamValueMatches(header string, raw json.RawMessage, valueType string) bool {
	switch valueType {
	case "string":
		var body string
		return json.Unmarshal(raw, &body) == nil && header == body
	case "boolean":
		var body bool
		return json.Unmarshal(raw, &body) == nil && header == strconv.FormatBool(body)
	case "integer":
		body, ok := canonicalMCPMirrorInteger(raw)
		if !ok {
			return false
		}
		return header == body
	default:
		return false
	}
}

// encodeMCPHeaderValue implements MCP 2026-07-28 Streamable HTTP, Request
// Metadata / Value Encoding. Empty values are encoded to preserve them over
// HTTP's empty/omitted and whitespace normalization. Partial sentinels are also
// encoded to round-trip through decodeMCPWireValue's existing reserved markers.
// https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#value-encoding
func encodeMCPHeaderValue(value string) string {
	unsafe := value == "" || strings.TrimSpace(value) != value || strings.HasPrefix(value, "=?base64?") || strings.HasSuffix(value, "?=")
	for i := range len(value) {
		if (value[i] < 0x20 || value[i] > 0x7e) && value[i] != '\t' {
			unsafe = true
		}
	}
	if unsafe {
		return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(value)) + "?="
	}
	return value
}

// canonicalMCPMirrorInteger uses decimal integer spelling (HTTP Value Encoding)
// and the ±(2^53-1) domain from MCP tools#x-mcp-header. Numeric comparison accepts
// integral JSON spellings such as 42.0, as HTTP Server Validation recommends.
// Bound exponents before exact arithmetic, like tools.safeHeaderEnumInteger.
func canonicalMCPMirrorInteger(raw json.RawMessage) (string, bool) {
	text := string(bytes.TrimSpace(raw))
	if !json.Valid(raw) {
		return "", false
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) || math.Trunc(f) != f || f > float64(maxMCPMirrorInteger) || f < -float64(maxMCPMirrorInteger) {
		return "", false
	}
	if f == 0 {
		mantissa, _, _ := strings.Cut(strings.ToLower(text), "e")
		for _, c := range mantissa {
			if c >= '1' && c <= '9' {
				return "", false
			}
		}
		return "0", true
	}
	n, ok := new(big.Rat).SetString(text)
	if !ok || !n.IsInt() || !n.Num().IsInt64() {
		return "", false
	}
	value := n.Num().Int64()
	if value > maxMCPMirrorInteger || value < -maxMCPMirrorInteger {
		return "", false
	}
	return strconv.FormatInt(value, 10), true
}

// synthesizeMCPRequestHeaders follows MCP 2026-07-28 Request Metadata:
// Mcp-Method for requests; Mcp-Name from tools/call and prompts/get params.name,
// or resources/read params.uri. Sending Messages explicitly leaves notification
// header requirements undefined and forbids responses; neither gets synthesis.
// Custom Headers / Client Behavior selects exact property paths; Server Behavior
// for Custom Headers requires omission for null or absent values.
func synthesizeMCPRequestHeaders(frame MCPFrame, baseline *tools.ToolBaseline) (http.Header, error) {
	headers := make(http.Header)
	if frame.Method == "" || isRPCNotification(frame.ID) {
		return headers, nil
	}
	if frame.ParseErr != nil {
		return nil, fmt.Errorf("invalid request metadata")
	}
	headers.Set(listenerMCPMethod, frame.Method)
	switch frame.Method {
	case methodToolsCall, methodResourcesRead, methodPromptsGet:
		if frame.RoutingNameErr != nil || !frame.RoutingNamePresent || frame.RoutingName == "" {
			return nil, fmt.Errorf("missing request routing name")
		}
		headers.Set(listenerMCPName, encodeMCPHeaderValue(frame.RoutingName))
	}
	if frame.Method != methodToolsCall {
		return headers, nil
	}
	contract := baseline.HeaderContract(frame.RoutingName)
	if contract.State == tools.HeaderContractUnknown || contract.State == tools.HeaderContractInvalid {
		return nil, fmt.Errorf("tool header contract unavailable or invalid")
	}
	for _, binding := range contract.Bindings {
		raw, present, ok := argumentAtPath(frame.Args, binding.Path)
		if !ok {
			return nil, fmt.Errorf("invalid argument path for mirrored parameter")
		}
		if !present || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		var value string
		switch binding.Type {
		case "string":
			if json.Unmarshal(raw, &value) != nil {
				return nil, fmt.Errorf("mirrored argument must be a string")
			}
		case "boolean":
			var boolean bool
			if json.Unmarshal(raw, &boolean) != nil {
				return nil, fmt.Errorf("mirrored argument must be a boolean")
			}
			value = strconv.FormatBool(boolean)
		case "integer":
			value, ok = canonicalMCPMirrorInteger(raw)
			if !ok {
				return nil, fmt.Errorf("mirrored argument must be a safe integer")
			}
		default:
			return nil, fmt.Errorf("unsupported mirrored parameter type")
		}
		headers.Set("Mcp-Param-"+binding.HeaderName, encodeMCPHeaderValue(value))
	}
	return headers, nil
}
