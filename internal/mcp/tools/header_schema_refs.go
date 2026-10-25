// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Instance-data keywords do not ordinarily contain schema annotations. A local
// reference can nevertheless select their contents as a schema (JSON Schema core
// 2020-12 section 9.4.2 leaves this behavior undefined). Inspect such targets as
// unreachable schemas rather than allowing an implementation-dependent binding.
// No reference is fetched: this checks only resources present in inputSchema.
func checkHeaderSchemaReferences(root map[string]any) error {
	type reference struct {
		base  *url.URL
		value string
	}
	type resource struct {
		value any
		data  bool
	}
	resources := make(map[string][]resource)
	anchors := make(map[string][]any)
	var refs []reference
	base, _ := url.Parse("https://mcp.invalid/input-schema")
	resources[base.String()] = []resource{{value: root}}
	var indexData func(any, *url.URL, int)
	indexData = func(value any, base *url.URL, depth int) {
		if depth > maxSchemaDepth {
			return
		}
		switch node := value.(type) {
		case []any:
			for _, child := range node {
				indexData(child, base, depth+1)
			}
		case map[string]any:
			id, _ := node["$id"].(string)
			if id == "" {
				id, _ = node["id"].(string)
			}
			if id != "" {
				if parsed, err := url.Parse(id); err == nil {
					base = base.ResolveReference(parsed)
					if base.Fragment == "" {
						resources[base.String()] = append(resources[base.String()], resource{value, true})
					} else {
						anchors[base.String()] = append(anchors[base.String()], value)
					}
				}
			}
			for _, key := range []string{"$anchor", "$dynamicAnchor"} {
				if name, ok := node[key].(string); ok {
					anchor := *base
					anchor.Fragment, anchor.RawFragment = name, ""
					anchors[anchor.String()] = append(anchors[anchor.String()], value)
				}
			}
			for _, child := range node {
				indexData(child, base, depth+1)
			}
		}
	}
	var collect func(any, *url.URL, int)
	collect = func(value any, base *url.URL, depth int) {
		if depth > maxSchemaDepth {
			return
		} // The ordinary walker enforces this bound.
		switch node := value.(type) {
		case []any:
			for _, child := range node {
				collect(child, base, depth+1)
			}
		case map[string]any:
			id, _ := node["$id"].(string)
			if id == "" {
				id, _ = node["id"].(string)
			} // draft-04 and earlier
			if id != "" {
				if parsed, err := url.Parse(id); err == nil {
					base = base.ResolveReference(parsed)
					resourceURL := *base
					resourceURL.Fragment, resourceURL.RawFragment = "", ""
					if base.Fragment == "" {
						resources[resourceURL.String()] = append(resources[resourceURL.String()], resource{value: value})
					}
				}
			}
			for key, child := range node {
				switch key {
				case "$ref", "$dynamicRef", "$recursiveRef":
					if ref, ok := child.(string); ok {
						refs = append(refs, reference{base, ref})
					}
				case "enum", "const", "default", "examples":
					indexData(child, base, depth+1)
				case "x-mcp-header":
				default:
					if headerSchemaNameMap(key) {
						if entries, ok := child.(map[string]any); ok {
							for _, schema := range entries {
								collect(schema, base, depth+1)
							}
							continue
						}
					}
					collect(child, base, depth+1)
				}
			}
		}
	}
	collect(root, base, 0)
	seen := make(map[string]bool)
	for i := 0; i < len(refs); i++ {
		ref := refs[i]
		parsed, err := url.Parse(ref.value)
		if err != nil {
			continue
		}
		resolved := ref.base.ResolveReference(parsed)
		if seen[resolved.String()] {
			continue
		}
		seen[resolved.String()] = true
		pointer := resolved.Fragment // net/url has already decoded URI percent escapes.
		targets := append([]any(nil), anchors[resolved.String()]...)
		resolved.Fragment, resolved.RawFragment = "", ""
		for _, resource := range resources[resolved.String()] {
			target, nonSchema := headerSchemaPointer(resource.value, pointer)
			if resource.data && pointer == "" {
				target = resource.value
			}
			if target != nil && (resource.data || nonSchema) {
				targets = append(targets, target)
			}
		}
		for _, target := range targets {
			var bindings []HeaderBinding
			if err := walkHeaderSchemaAt(target, nil, false, 0, make(map[string]struct{}), &bindings); err != nil {
				return fmt.Errorf("referenced non-schema location: %w", err)
			}
			// A selected target can itself contain references into other instance data.
			collect(target, resolved, 0)
		}
	}
	return nil
}

func headerSchemaNameMap(key string) bool {
	switch key {
	case "properties", "$defs", "patternProperties", "dependentSchemas", "definitions", "dependencies", "dependentRequired":
		return true
	}
	return false
}

// RFC 6901 sections 4 and 6: URI fragment decoding precedes ~1 and ~0.
// The boolean distinguishes data/name-map locations from schema locations the
// ordinary walker already inspected, even when a property is named "default".
func headerSchemaPointer(value any, pointer string) (any, bool) {
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}
	data, nameMap := false, false
	for _, raw := range strings.Split(pointer[1:], "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch node := value.(type) {
		case map[string]any:
			if !nameMap && (token == "enum" || token == "const" || token == "default" || token == "examples") {
				data = true
			}
			nameMap = !nameMap && headerSchemaNameMap(token)
			var exists bool
			value, exists = node[token]
			if !exists {
				return nil, false
			}
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(node) || strconv.Itoa(index) != token {
				return nil, false
			}
			value, nameMap = node[index], false
		default:
			return nil, false
		}
	}
	return value, data || nameMap
}
