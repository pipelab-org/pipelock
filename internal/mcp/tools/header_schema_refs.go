// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package tools

import "fmt"

// checkHeaderSchemaReferences refuses an x-mcp-header key that a reference
// could apply as a schema although walkHeaderSchema never vetted it.
//
// JSON Schema core 2020-12 §9.4.2 leaves a reference into a non-schema
// location (instance data, or a name map such as properties itself) to the
// implementation, and implementations also disagree on base URIs, "id" versus
// "$id", draft-07 $ref siblings and pointer escapes. Imitating one resolver
// therefore leaves bindings another resolver applies. Instead this refuses the
// only combination under which any resolver can apply an unvetted annotation:
// a reference keyword (core §8.2.3.1 $ref, §8.2.3.2 $dynamicRef, 2019-09
// $recursiveRef) together with an x-mcp-header key outside the walker's
// accepted properties-path bindings. Every object the walker does not inspect
// as a schema is instance data or a name-map container, so comparing counts
// covers both without resolving anything. Nothing is fetched.
func checkHeaderSchemaReferences(root map[string]any, vetted int) error {
	var references, annotations int
	countHeaderSchemaKeys(root, &references, &annotations)
	if references > 0 && annotations > vetted {
		return fmt.Errorf("x-mcp-header outside a schema location is reachable by reference")
	}
	return nil
}

// countHeaderSchemaKeys counts keys across the whole decoded document, with no
// depth cut-off that could leave a key uncounted. encoding/json already bounds
// nesting during decoding, and each value is visited once.
func countHeaderSchemaKeys(value any, references, annotations *int) {
	switch node := value.(type) {
	case []any:
		for _, child := range node {
			countHeaderSchemaKeys(child, references, annotations)
		}
	case map[string]any:
		for key, child := range node {
			switch key {
			case "$ref", "$dynamicRef", "$recursiveRef":
				*references++
			case "x-mcp-header":
				*annotations++
			}
			countHeaderSchemaKeys(child, references, annotations)
		}
	}
}
