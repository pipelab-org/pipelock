// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestExtractHeaderBindings_ReferencedInstanceData(t *testing.T) {
	annotation := `{"type":"string","x-mcp-header":"Region"}`
	for _, keyword := range []string{"default", "examples", "enum", "const"} {
		for _, refKeyword := range []string{"$ref", "$dynamicRef", "$recursiveRef"} {
			pointer, data := "#/"+keyword, annotation
			if keyword == "examples" || keyword == "enum" {
				pointer += "/0"
				data = "[" + data + "]"
			}
			t.Run(keyword+"/"+refKeyword, func(t *testing.T) {
				schema := fmt.Sprintf(`{"type":"object","properties":{"region":{%q:%q}},%q:%s}`, refKeyword, pointer, keyword, data)
				if _, err := ExtractHeaderBindings(json.RawMessage(schema)); err == nil {
					t.Fatal("annotation referenced through instance data accepted")
				}
			})
		}
	}
	for _, tc := range []struct {
		name, schema string
		invalid      bool
	}{
		{"escaped and encoded pointer", `{"type":"object","properties":{"region":{"$ref":"#/%64efault/a~1b~0c"}},"default":{"a/b~c":` + annotation + `}}`, true},
		{"nested resource", `{"$id":"https://api.vendor.example/schema","type":"object","properties":{"region":{"$ref":"library#/default"}},"$defs":{"local":{"$id":"library","default":` + annotation + `}}}`, true},
		{"root identifier", `{"$id":"https://api.vendor.example/schema","type":"object","properties":{"region":{"$ref":"https://api.vendor.example/schema#/default"}},"default":` + annotation + `}`, true},
		{"anchor in data", `{"type":"object","properties":{"region":{"$ref":"#R"}},"default":{"$anchor":"R","type":"string","x-mcp-header":"Region"}}`, true},
		{"id in data", `{"type":"object","properties":{"region":{"$ref":"https://api.vendor.example/data"}},"default":{"$id":"https://api.vendor.example/data","type":"string","x-mcp-header":"Region"}}`, true},
		{"fragment id in data", `{"type":"object","properties":{"region":{"$ref":"#R"}},"default":{"id":"#R","type":"string","x-mcp-header":"Region"}}`, true},
		{"nested reference", `{"type":"object","properties":{"region":{"$ref":"#/default"}},"default":{"$ref":"#/examples/0"},"examples":[` + annotation + `]}`, true},
		{"name map target", `{"type":"object","properties":{"region":{"$ref":"#/properties"},"x-mcp-header":{"type":"string"}}}`, true},
		// A resolver applying properties itself as a schema reads these string
		// entries as type and x-mcp-header keywords: a real binding on region.
		{"string name-map entries", `{"type":"object","properties":{"region":{"$ref":"#/properties"},"type":"string","x-mcp-header":"Region"}}`, true},
		// jsonschema 4.26.0 resolves each of these to the default annotation.
		// 2020-12 does not define "id"; draft-07 ignores every $ref sibling.
		{"undefined id sibling", `{"type":"object","properties":{"region":{"id":"https://api.vendor.example/a","$ref":"#/default"}},"default":` + annotation + `}`, true},
		{"draft-07 ignored $id sibling", `{"type":"object","properties":{"region":{"$id":"https://api.vendor.example/a","$ref":"#/default"}},"default":` + annotation + `}`, true},
		{"undecodable percent escape", `{"type":"object","properties":{"region":{"$ref":"#/default/%zz"}},"default":{"%zz":` + annotation + `}}`, true},
		// Resolution is never attempted, so an external target is not proof
		// the local data is unreachable: a resolver may map it to this document.
		{"external reference", `{"type":"object","properties":{"region":{"$ref":"https://api.vendor.example/other#/default"}},"default":` + annotation + `}`, true},
		{"referenced document with literal data", `{"type":"object","default":` + annotation + `,"examples":[` + annotation + `],"properties":{"region":{"type":"string","x-mcp-header":"Region"},"other":{"$ref":"#/$defs/Text"}},"$defs":{"Text":{"type":"string"}}}`, true},
		{"unreferenced literal data", `{"type":"object","default":` + annotation + `,"examples":[` + annotation + `],"properties":{"region":{"type":"string","x-mcp-header":"Region"}}}`, false},
		{"unreferenced annotation-named property", `{"type":"object","properties":{"x-mcp-header":{"type":"string"}},"dependentRequired":{"x-mcp-header":["a"]}}`, false},
		{"annotation-shaped property name", `{"type":"object","properties":{"default":{"type":"string","x-mcp-header":"Region"},"alias":{"$ref":"#/properties/default"}}}`, false},
		{"reference-shaped instance data", `{"type":"object","default":{"$ref":"#/examples/0"},"examples":[{"type":"string"}]}`, false},
		{"referenced valid binding", `{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"other":{"$ref":"#/$defs/Text"}},"$defs":{"Text":{"type":"string"}}}`, false},
		{"unannotated data target", `{"type":"object","properties":{"region":{"$ref":"#/default"}},"default":{"type":"string"}}`, false},
		{"reference cycle", `{"type":"object","properties":{"region":{"$ref":"#/default"}},"default":{"$ref":"#/default"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExtractHeaderBindings(json.RawMessage(tc.schema))
			if (err != nil) != tc.invalid {
				t.Fatalf("invalid=%v err=%v", tc.invalid, err)
			}
		})
	}
}

// The reference check counts keys in instance data, which the ordinary walker
// skips and whose depth no walker bound limits. Data far deeper than any walker
// depth is still counted, and the same depth without an annotation stays valid.
func TestExtractHeaderBindings_ReferenceCheckCountsDeepData(t *testing.T) {
	levels := 4 * maxSchemaDepth
	for _, tc := range []struct {
		leaf    string
		invalid bool
	}{{`{"x-mcp-header":"Region"}`, true}, {`{"title":"Region"}`, false}} {
		data := strings.Repeat(`{"a":`, levels) + tc.leaf + strings.Repeat(`}`, levels)
		schema := `{"type":"object","properties":{"region":{"$ref":"#/default"}},"default":` + data + `}`
		if _, err := ExtractHeaderBindings(json.RawMessage(schema)); (err != nil) != tc.invalid {
			t.Fatalf("leaf %s: invalid=%v err=%v", tc.leaf, tc.invalid, err)
		}
	}
}
