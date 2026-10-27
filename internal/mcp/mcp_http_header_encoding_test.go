// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

func TestMCPHeaderEncodingRoundTrip(t *testing.T) {
	for _, value := range []string{"", "ASCII", "42", "false", "東京", " leading", "trailing ", "a\tb", "\tleading", "\r\n", "\x00", "\x7f", "=?base64?literal?=", "=?base64?partial", "partial?="} {
		t.Run(value, func(t *testing.T) {
			raw, _ := json.Marshal(value)
			encoded := encodeMCPHeaderValue(value)
			decoded, ok := decodeMCPHeaderValue(encoded)
			if !ok || decoded != value || !mcpParamValueMatches(decoded, raw, "string") {
				t.Fatalf("%q -> %q -> %q accepted=%v", value, encoded, decoded, ok)
			}
			frame := ParseMCPFrame([]byte(bridgeHeaderCall(`{"region":` + string(raw) + `}`)))
			baseline := headerBaselineForTest(t, bridgeHeaderSchema)
			headers, err := synthesizeMCPRequestHeaders(frame, baseline)
			if err != nil || !validateMCPParamHeaders(headers, frame, baseline) {
				t.Fatalf("validator rejected synthesis: %v %v", headers, err)
			}
			// Conversely, an accepted alternate wire spelling re-encodes to the same
			// body value, including Base64 for otherwise plain ASCII.
			alternate := "=?base64?" + base64.StdEncoding.EncodeToString([]byte(value)) + "?="
			h := http.Header{"Mcp-Param-Region": {alternate}}
			if !validateMCPParamHeaders(h, frame, baseline) {
				t.Fatalf("alternate rejected: %q", alternate)
			}
		})
	}
}

func FuzzMCPHeaderEncodingRoundTrip(f *testing.F) {
	for _, s := range []string{"", "a\tb", "\r\n", "東京", "=?base64?test?="} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if !utf8.ValidString(value) {
			t.Skip()
		}
		decoded, ok := decodeMCPHeaderValue(encodeMCPHeaderValue(value))
		if !ok || decoded != value {
			t.Fatalf("failed to round-trip %q", value)
		}
		raw, _ := json.Marshal(value)
		frame := ParseMCPFrame([]byte(bridgeHeaderCall(`{"region":` + string(raw) + `}`)))
		headers := http.Header{"Mcp-Param-Region": {encodeMCPHeaderValue(value)}}
		if !validateMCPParamHeaders(headers, frame, headerBaselineForTest(t, bridgeHeaderSchema)) {
			t.Fatalf("listener rejected encoded value %q", value)
		}
	})
}

func TestMCPHeaderIntegerCanonicalization(t *testing.T) {
	for _, tc := range []struct {
		raw, want string
		ok        bool
	}{
		{"42.0", "42", true},
		{"4.2e1", "42", true},
		{"-7", "-7", true},
		{"-0.0", "0", true},
		{"9007199254740991", "9007199254740991", true},
		{"-9007199254740991", "-9007199254740991", true},
		{"9007199254740992", "", false},
		{"-9007199254740992", "", false},
		{"1.5", "", false},
		{"42.000000000000000001", "", false},
		{"1e999999999", "", false},
		{"1e-999999999", "", false},
		{"0e999999999", "0", true},
		{`"42"`, "", false},
		{"null", "", false},
		{"true", "", false},
		{"42/1", "", false},
		{"+42", "", false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, ok := canonicalMCPMirrorInteger(json.RawMessage(tc.raw))
			if got != tc.want || ok != tc.ok {
				t.Fatalf("got=%q,%v want=%q,%v", got, ok, tc.want, tc.ok)
			}
			if ok && !mcpParamValueMatches(got, json.RawMessage(tc.raw), "integer") {
				t.Fatal("listener rejected emitted integer")
			}
		})
	}
}

func TestMCPStandardRoutingSynthesis(t *testing.T) {
	for _, tc := range []struct{ method, params, want string }{
		{methodToolsCall, `"name":"echo"`, "echo"},
		{methodPromptsGet, `"name":"prompt"`, "prompt"},
		{methodResourcesRead, `"uri":"file:///東京"`, "=?base64?ZmlsZTovLy/mnbHkuqw=?="},
		{"tools/list", "", ""},
		{"resources/list", "", ""},
		{"ping", "", ""},
	} {
		t.Run(tc.method, func(t *testing.T) {
			frame := ParseMCPFrame([]byte(currentWireBody(1, tc.method, tc.params)))
			headers, err := synthesizeMCPRequestHeaders(frame, headerBaselineForTest(t, `{"type":"object"}`))
			if err != nil || headers.Get(listenerMCPMethod) != tc.method || headers.Get(listenerMCPName) != tc.want {
				t.Fatalf("headers=%v err=%v", headers, err)
			}
		})
	}
	for _, msg := range []string{jsonNotificationsInitialized, `{"jsonrpc":"2.0","id":1,"result":{}}`} {
		headers, err := synthesizeMCPRequestHeaders(ParseMCPFrame([]byte(msg)), nil)
		if err != nil || len(headers) != 0 {
			t.Fatalf("non-request headers=%v err=%v", headers, err)
		}
	}
}

func TestMCPHeaderSynthesisRefusesInvalidArguments(t *testing.T) {
	for _, tc := range []struct{ name, kind, args string }{
		{"string type", "string", `{"nested":{"value":{}}}`},
		{"boolean type", "boolean", `{"nested":{"value":"true"}}`},
		{"integer type", "integer", `{"nested":{"value":1.5}}`},
		{"unsafe integer", "integer", `{"nested":{"value":9007199254740992}}`},
		{"invalid path", "string", `{"nested":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseline := tools.NewToolBaseline()
			schema := fmt.Sprintf(`{"type":"object","properties":{"nested":{"type":"object","properties":{"value":{"type":%q,"x-mcp-header":"Value"}}}}}`, tc.kind)
			if err := baseline.SetToolHeaderBindings([]tools.ToolDef{{Name: "echo", InputSchema: json.RawMessage(schema)}}); err != nil {
				t.Fatal(err)
			}
			frame := ParseMCPFrame([]byte(bridgeHeaderCall(tc.args)))
			if headers, err := synthesizeMCPRequestHeaders(frame, baseline); err == nil {
				t.Fatalf("invalid argument synthesized: %v", headers)
			}
		})
	}
	for _, msg := range []string{
		currentWireBody(1, methodToolsCall, `"arguments":{}`),
		currentWireBody(1, methodPromptsGet, `"name":null`),
		currentWireBody(1, methodResourcesRead, `"uri":42`),
	} {
		if headers, err := synthesizeMCPRequestHeaders(ParseMCPFrame([]byte(msg)), nil); err == nil {
			t.Fatalf("invalid routing synthesized: %v", headers)
		}
	}
}
