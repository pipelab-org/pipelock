// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/extract"
)

const (
	maxToolHeaderBindings    = 256
	maxToolHeaderSchemaDepth = 32
)

// HeaderBinding identifies one primitive tool argument that a 2026-07-28
// inputSchema mirrors into Mcp-Param-{HeaderName}.
type HeaderBinding struct {
	HeaderName string
	Path       []string
	Type       string
}

// HeaderContractState distinguishes structural knowledge from delivery history
// and from the drift baseline's trust decisions.
type HeaderContractState uint8

const (
	HeaderContractUnknown HeaderContractState = iota
	HeaderContractValidWithBindings
	HeaderContractValidWithoutBindings
	HeaderContractInvalid
)

// HeaderContract is a schema observation, not proof of client delivery or approval.
// Future internal discovery can record this state without admitting knownTools.
type HeaderContract struct {
	State    HeaderContractState
	Bindings map[string]HeaderBinding
	Reason   string
}

// headerBindingsForDefs validates contracts before the baseline lock is held.
// Invalid observations remain explicit: deleting them would mean unknown again.
func headerBindingsForDefs(defs []ToolDef) map[string]HeaderContract {
	prepared := make(map[string]HeaderContract, len(defs))
	for _, def := range defs {
		bindings, err := ExtractHeaderBindings(def.InputSchema)
		contract := HeaderContract{State: HeaderContractValidWithoutBindings, Bindings: make(map[string]HeaderBinding, len(bindings))}
		if err != nil {
			contract = HeaderContract{State: HeaderContractInvalid, Reason: err.Error()}
		} else {
			for _, binding := range bindings {
				binding.Path = append([]string(nil), binding.Path...)
				contract.Bindings[strings.ToLower(binding.HeaderName)] = binding
			}
			if len(bindings) > 0 {
				contract.State = HeaderContractValidWithBindings
			}
		}
		// MCP tools#tool-names says names SHOULD be unique within a server.
		// Conflicting definitions cannot identify one exact per-name contract.
		if _, duplicate := prepared[def.Name]; duplicate {
			contract = HeaderContract{State: HeaderContractInvalid, Reason: "duplicate tool definition"}
		}
		prepared[def.Name] = contract
	}
	return prepared
}

// CanAdmitHeaderBindings includes rejected contracts in the bounded registry.
func (tb *ToolBaseline) CanAdmitHeaderBindings(defs []ToolDef) bool {
	if tb == nil {
		return true
	}
	prepared := headerBindingsForDefs(defs)
	names := make([]string, 0, len(prepared))
	for name := range prepared {
		names = append(names, name)
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return namesFitCapacity(tb.headerBindings, names)
}

// SetToolHeaderBindings records structural observations only. It does not mark
// tools client-seen, approve drift, or satisfy an inventory approval.
func (tb *ToolBaseline) SetToolHeaderBindings(defs []ToolDef) error {
	prepared := headerBindingsForDefs(defs)
	names := make([]string, 0, len(prepared))
	for name := range prepared {
		names = append(names, name)
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.headerBindings == nil {
		tb.headerBindings = make(map[string]HeaderContract)
	}
	if !namesFitCapacityWithPending(tb.headerBindings, tb.pendingTools, names) {
		return ErrBaselineCapacity
	}
	tb.inventorySequence++
	for name, contract := range prepared {
		tb.headerBindings[name] = contract
		if tb.headerContractVersions == nil {
			tb.headerContractVersions = make(map[string]uint64)
		}
		tb.headerContractVersions[name] = tb.inventorySequence
	}
	return nil
}

// HeaderContract returns an isolated snapshot of a tool's structural contract.
func (tb *ToolBaseline) HeaderContract(toolName string) HeaderContract {
	if tb == nil {
		return HeaderContract{State: HeaderContractUnknown}
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	contract := tb.headerBindings[toolName]
	if contract.Bindings != nil {
		out := make(map[string]HeaderBinding, len(contract.Bindings))
		for name, binding := range contract.Bindings {
			binding.Path = append([]string(nil), binding.Path...)
			out[name] = binding
		}
		contract.Bindings = out
	}
	return contract
}

// HeaderBindings is the valid-contract compatibility view. Callers deciding
// whether a tool is rejected must use HeaderContract instead.
func (tb *ToolBaseline) HeaderBindings(toolName string) (map[string]HeaderBinding, bool) {
	contract := tb.HeaderContract(toolName)
	return contract.Bindings, contract.State == HeaderContractValidWithBindings || contract.State == HeaderContractValidWithoutBindings
}

// ExtractHeaderBindings validates and extracts x-mcp-header annotations along
// property-only paths, as required by MCP 2026-07-28. An annotation below an
// array, composition, conditional, or $ref is rejected instead of silently
// becoming a different security contract from the client.
func ExtractHeaderBindings(schema json.RawMessage) ([]HeaderBinding, error) {
	if len(schema) == 0 {
		return nil, nil
	}
	var root any
	if err := extract.DecodeJSON(schema, &root); err != nil {
		return nil, fmt.Errorf("decode input schema: %w", err)
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("input schema must be an object")
	}
	var bindings []HeaderBinding
	seen := make(map[string]struct{})
	if err := walkHeaderSchema(obj, nil, seen, &bindings); err != nil {
		return nil, err
	}
	return bindings, nil
}

// MCP 2026-07-28, Streamable HTTP "Schema Extension" requires an exact
// properties-only path. JSON Schema core 2020-12 §9.4.2 says keyword semantics
// determine subschema locations, not arbitrary JSON object keys:
// https://json-schema.org/draft/2020-12/json-schema-core#section-9.4.2
func walkHeaderSchema(node map[string]any, path []string, seen map[string]struct{}, out *[]HeaderBinding) error {
	return walkHeaderSchemaAt(node, path, true, 0, seen, out)
}

func walkHeaderSchemaAt(value any, path []string, reachable bool, depth int, seen map[string]struct{}, out *[]HeaderBinding) error {
	if depth > maxSchemaDepth {
		return fmt.Errorf("input schema exceeds header traversal depth")
	}
	// MCP tools#x-mcp-header rejects a tool for an invalid annotation, not for
	// schema shapes outside 2020-12 (core §4.3.1 allows only object and boolean
	// schemas). Draft-07 tuple "items" arrays and other malformed keyword values
	// carry no binding, so they are searched as unreachable schemas: a real
	// annotation inside one still rejects, and scalars cannot hold one.
	node, ok := value.(map[string]any)
	if !ok {
		if items, isArray := value.([]any); isArray {
			for _, item := range items {
				if err := walkHeaderSchemaAt(item, path, false, depth+1, seen, out); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if raw, exists := node["x-mcp-header"]; exists {
		// MCP tools#x-mcp-header and RFC 9110 §5.1: token names, nonempty,
		// case-insensitively unique, on supported primitives at property paths.
		name, ok := raw.(string)
		if !reachable || len(path) == 0 || len(path) > maxToolHeaderSchemaDepth || !ok || !validHTTPFieldToken(name) {
			return fmt.Errorf("invalid x-mcp-header annotation at %s", strings.Join(path, "."))
		}
		typeName, err := headerPrimitiveType(node)
		if err != nil {
			return fmt.Errorf("x-mcp-header %q: %w", name, err)
		}
		folded := strings.ToLower(name)
		if _, duplicate := seen[folded]; duplicate {
			return fmt.Errorf("duplicate x-mcp-header %q", name)
		}
		seen[folded] = struct{}{}
		*out = append(*out, HeaderBinding{HeaderName: name, Path: append([]string(nil), path...), Type: typeName})
		if len(*out) > maxToolHeaderBindings {
			return fmt.Errorf("input schema exceeds %d x-mcp-header annotations", maxToolHeaderBindings)
		}
	}
	for key, child := range node {
		switch key {
		// Core §8.2.4 ($defs), §10.3.2 (object applicators): these are maps
		// of schemas. Draft-07 validation §§6.5.7 and 9 add dependencies
		// and definitions. Entry names are not annotation keywords.
		// https://json-schema.org/draft-07/draft-handrews-json-schema-validation-01
		case "properties", "$defs", "patternProperties", "dependentSchemas", "definitions", "dependencies":
			children, ok := child.(map[string]any)
			if !ok {
				if err := walkHeaderSchemaAt(child, path, false, depth+1, seen, out); err != nil {
					return err
				}
				continue
			}
			for name, schema := range children {
				childPath := append(append([]string(nil), path...), name)
				if err := walkHeaderSchemaAt(schema, childPath, reachable && key == "properties", depth+1, seen, out); err != nil {
					return err
				}
			}
		// Core §§10.2, 10.3, 11 and validation §8.5 define single subschemas.
		// Draft-07 validation §6.4.2 also defines additionalItems as a schema.
		// Only properties is a static MCP path; even unused definitions are checked.
		case "items", "additionalItems", "contains", "additionalProperties", "unevaluatedProperties", "propertyNames", "unevaluatedItems", "not", "if", "then", "else", "contentSchema":
			if err := walkHeaderSchemaAt(child, path, false, depth+1, seen, out); err != nil {
				return err
			}
		case "allOf", "anyOf", "oneOf", "prefixItems":
			if err := walkHeaderSchemaAt(child, path, false, depth+1, seen, out); err != nil {
				return err
			}
			// Validation §§6.1.2, 6.1.3, 9.2, 9.5: enum, const, default,
			// examples contain instance data. Core §6.5 treats unknown keywords
			// as annotations. Neither supplies additional subschema positions.
		}
	}
	return nil
}

func supportedHeaderType(t string) bool { return t == "string" || t == "integer" || t == "boolean" }

func headerPrimitiveType(node map[string]any) (string, error) {
	// Validation 2020-12 §6.1.1 permits type arrays. MCP's primitive
	// restriction plus null-omission (HTTP "Server Behavior for Custom
	// Headers") is interpreted as one supported non-null type plus null.
	// This is a supported interpretation, not an explicit MCP union rule.
	// https://json-schema.org/draft/2020-12/json-schema-validation#section-6.1.1
	if raw, exists := node["type"]; exists {
		if t, ok := raw.(string); ok && supportedHeaderType(t) {
			return t, nil
		}
		if types, ok := raw.([]any); ok {
			primitive := ""
			nullSeen := false
			for _, rawType := range types {
				t, ok := rawType.(string)
				if !ok {
					return "", fmt.Errorf("type array contains a non-string")
				}
				if t == "null" && !nullSeen {
					nullSeen = true
					continue
				}
				if !supportedHeaderType(t) || primitive != "" {
					return "", fmt.Errorf("type array has no single supported primitive")
				}
				primitive = t
			}
			if primitive != "" {
				return primitive, nil
			}
		}
		return "", fmt.Errorf("unsupported primitive type")
	}
	// Validation §6.1.2: enum restricts the value to its listed instances
	// without requiring type, and §6.1.3 makes const equivalent to a
	// one-value enum. Every non-null value must prove the SAME MCP primitive
	// domain; mixed, null-only, object, array and number domains are refused.
	// A null member is allowed for the reason a nullable type array is: MCP
	// omits the header for a null argument.
	// https://json-schema.org/draft/2020-12/json-schema-validation#section-6.1.2
	values, ok := node["enum"].([]any)
	if constValue, hasConst := node["const"]; !ok && hasConst {
		values, ok = []any{constValue}, true
	}
	if !ok || len(values) == 0 {
		return "", fmt.Errorf("no supported primitive domain")
	}
	kind := ""
	for _, value := range values {
		if value == nil {
			continue
		}
		current := ""
		switch v := value.(type) {
		case string:
			current = "string"
		case bool:
			current = "boolean"
		case json.Number:
			// Validation §6.1.1 defines integer by mathematical value, not
			// lexical form. MCP tools#x-mcp-header bounds integers to ±(2^53-1).
			if safeHeaderEnumInteger(v) {
				current = "integer"
			}
		}
		if current == "" || (kind != "" && current != kind) {
			return "", fmt.Errorf("enum has no single supported primitive kind")
		}
		kind = current
	}
	if kind == "" {
		return "", fmt.Errorf("enum has no single supported primitive kind")
	}
	return kind, nil
}

// Bound the numeric domain before exact rational parsing: huge exponents in
// otherwise small JSON must not allocate an exponent-sized integer. The bound
// is MCP's published safe-integer range, not a schema-size heuristic.
func safeHeaderEnumInteger(value json.Number) bool {
	text := string(value)
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) || math.Trunc(f) != f || f < -9007199254740991 || f > 9007199254740991 {
		return false
	}
	if f == 0 {
		mantissa, _, _ := strings.Cut(strings.ToLower(text), "e")
		for _, c := range mantissa {
			if c >= '1' && c <= '9' {
				return false
			}
		}
		return true
	}
	n, valid := new(big.Rat).SetString(text)
	return valid && n.IsInt() && n.Num().IsInt64() && n.Num().Int64() >= -9007199254740991 && n.Num().Int64() <= 9007199254740991
}

func validHTTPFieldToken(value string) bool {
	for i := range len(value) {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return value != ""
}

// FilterInvalidHeaderTools applies MCP 2026-07-28 tools#x-mcp-header's
// invalid-definition exclusion rule. Raw siblings and pagination metadata are
// preserved. The caller retains defs (including rejected tools) for the
// structural reservation, while only returned names become client-seen.
func FilterInvalidHeaderTools(line []byte, defs []ToolDef) ([]byte, []string, map[string]string, error) {
	contracts := headerBindingsForDefs(defs)
	rejected := make(map[string]string)
	for name, contract := range contracts {
		if contract.State == HeaderContractInvalid {
			rejected[name] = contract.Reason
		}
	}
	names := make([]string, 0, len(defs))
	for _, def := range defs {
		if _, invalid := rejected[def.Name]; !invalid {
			names = append(names, def.Name)
		}
	}
	if len(rejected) == 0 {
		return line, names, rejected, nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(line, &envelope); err != nil {
		return nil, nil, nil, err
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(envelope["result"], &result); err != nil {
		return nil, nil, nil, err
	}
	var rawTools []json.RawMessage
	if err := json.Unmarshal(result["tools"], &rawTools); err != nil {
		return nil, nil, nil, err
	}
	kept := make([]json.RawMessage, 0, len(rawTools))
	for _, raw := range rawTools {
		var def struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &def); err != nil {
			return nil, nil, nil, err
		}
		if _, invalid := rejected[def.Name]; !invalid {
			kept = append(kept, raw)
		}
	}
	// Every retained raw value already passed JSON decoding; these marshals
	// cannot fail and do not reinterpret numbers in schemas or extension data.
	result["tools"], _ = json.Marshal(kept)
	envelope["result"], _ = json.Marshal(result)
	filtered, err := json.Marshal(envelope)
	return filtered, names, rejected, err
}
