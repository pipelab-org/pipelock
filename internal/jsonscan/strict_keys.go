// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"unicode"
)

// DecodeStrict validates keys before binding one JSON value to a schema.
// Unknown fields reject and numbers retain their original decimal spelling.
func DecodeStrict(data []byte, target any) error {
	if err := ValidateKeys(data, MaxNestingDepth); err != nil {
		return err
	}
	typ := reflect.TypeOf(target)
	if typ == nil || typ.Kind() != reflect.Pointer || reflect.ValueOf(target).IsNil() {
		return &json.InvalidUnmarshalError{Type: typ}
	}
	if err := RejectStructAliases(data, typ); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	return dec.Decode(target)
}

var jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// RejectStructAliases refuses noncanonical spellings of typed JSON fields,
// recursively. Map keys remain application data, but map values are checked
// against their declared types. Custom unmarshallers own their nested schema.
func RejectStructAliases(data []byte, typ reflect.Type) error {
	return rejectSchemaNames(data, typ, schemaPolicy{canonical: true})
}

// RejectNonCanonicalFields adds canonical typed names to the existing
// RejectDuplicateKeys document policy. Use RejectStructAliases after another
// validator to retain that validator's numeric and nesting rules.
// The target supplies a schema and is never modified.
func RejectNonCanonicalFields(data []byte, target any) error {
	if err := RejectDuplicateKeys(data); err != nil {
		return err
	}
	return RejectStructAliases(data, reflect.TypeOf(target))
}

// RejectDuplicateFields rejects multiple names bound to the same typed field,
// while accepting a lone case alias. Application map keys remain case-sensitive.
// Optional canonical schemas require exact names inside those typed objects,
// allowing request wrappers to contain signed artifacts with a stricter policy.
// An interface schema, such as (*Signed)(nil), selects every implementing type.
// Custom unmarshallers own their nested schema, as with RejectStructAliases.
// This retains RejectDuplicateKeys' document policy; already validated inputs
// should use RejectDuplicateFieldsInValidatedJSON.
func RejectDuplicateFields(data []byte, target any, canonicalSchemas ...any) error {
	if err := RejectDuplicateKeys(data); err != nil {
		return err
	}
	return RejectDuplicateFieldsInValidatedJSON(data, target, canonicalSchemas...)
}

// RejectDuplicateFieldsInValidatedJSON checks only typed field bindings. Callers
// must first validate exact document keys using their existing validator. This
// preserves that validator's numeric, nesting, and trailing-data policies.
func RejectDuplicateFieldsInValidatedJSON(data []byte, target any, canonicalSchemas ...any) error {
	policy := schemaPolicy{}
	if len(canonicalSchemas) != 0 {
		policy.canonicalTypes = make(map[reflect.Type]bool, len(canonicalSchemas))
		for _, schema := range canonicalSchemas {
			typ := indirectType(reflect.TypeOf(schema))
			if typ != nil && typ.Kind() == reflect.Interface {
				policy.canonicalInterfaces = append(policy.canonicalInterfaces, typ)
				continue
			}
			policy.canonicalTypes[typ] = true
		}
	}
	return rejectSchemaNames(data, reflect.TypeOf(target), policy)
}

type schemaPolicy struct {
	canonical           bool
	canonicalTypes      map[reflect.Type]bool
	canonicalInterfaces []reflect.Type
}

func (p schemaPolicy) selectsCanonical(typ reflect.Type) bool {
	if p.canonicalTypes[typ] {
		return true
	}
	for _, iface := range p.canonicalInterfaces {
		if reflect.PointerTo(typ).Implements(iface) {
			return true
		}
	}
	return false
}

func indirectType(typ reflect.Type) reflect.Type {
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ
}

func rejectSchemaNames(data []byte, typ reflect.Type, policy schemaPolicy) error {
	typ = indirectType(typ)
	if typ == nil {
		return nil
	}
	if decodesItselfUnderV2(typ) {
		return fmt.Errorf("%w: %s decodes itself differently across Go JSON decoders", ErrDuplicateKey, typ)
	}
	if policy.selectsCanonical(typ) {
		policy.canonical = true
	}
	if typ.Kind() != reflect.Struct {
		return rejectNestedNames(data, typ, policy)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil // The consuming decoder owns type errors.
	}
	schema := cachedStructFields(typ)
	hazards := cachedSchemaHazards(typ)
	if hazards.unsupported {
		return fmt.Errorf("%w: %s has a json field shape that binds differently across Go JSON decoders", ErrDuplicateKey, typ)
	}
	seen := make(map[string]string, len(fields))
	for key, value := range fields {
		if hazards.depthFolds[FoldKey(key)] {
			return fmt.Errorf("%w: %q matches fields at different embedding depths of %s", ErrDuplicateKey, key, typ)
		}
		name, field, ok := boundField(schema, key)
		if !ok {
			continue // Preserve the consuming decoder's unknown-field policy.
		}
		if policy.canonical && key != name {
			return fmt.Errorf("%w: %q aliases %q (case-insensitive)", ErrCaseFoldedKey, key, name)
		}
		if previous, exists := seen[name]; exists {
			return fmt.Errorf("%w: %q and %q bind %q (case-insensitive)", ErrDuplicateKey, previous, key, name)
		}
		seen[name] = key
		if err := rejectNestedNames(value, field.typ, policy); err != nil {
			return err
		}
	}
	return nil
}

// encoding/json resolves exact names first, then the first folded match in
// field-index order after embedded-field dominance has removed ambiguities.
func boundField(schema map[string]schemaField, key string) (string, schemaField, bool) {
	if field, ok := schema[key]; ok && !field.ambiguous {
		return key, field, true
	}
	var name string
	var first schemaField
	found := false
	folded := FoldKey(key)
	for candidate, field := range schema {
		if field.ambiguous || FoldKey(candidate) != folded {
			continue
		}
		if !found || slices.Compare(field.index, first.index) < 0 {
			name, first, found = candidate, field, true
		}
	}
	return name, first, found
}

func rejectNestedNames(data []byte, typ reflect.Type, policy schemaPolicy) error {
	typ = indirectType(typ)
	if typ != nil && decodesItselfUnderV2(typ) {
		return fmt.Errorf("%w: %s decodes itself differently across Go JSON decoders", ErrDuplicateKey, typ)
	}
	if typ == nil || reflect.PointerTo(typ).Implements(jsonUnmarshalerType) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		return rejectSchemaNames(data, typ, policy)
	case reflect.Slice, reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return nil // The consuming decoder owns type errors.
		}
		for _, item := range items {
			if err := rejectNestedNames(item, typ.Elem(), policy); err != nil {
				return err
			}
		}
	case reflect.Map:
		var items map[string]json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return nil // The consuming decoder owns type errors.
		}
		for _, item := range items {
			if err := rejectNestedNames(item, typ.Elem(), policy); err != nil {
				return err
			}
		}
	}
	return nil
}

// schemaField records promotion priority without descending through recursive
// embedded pointers indefinitely. Ambiguous promoted fields are ignored by JSON.
type schemaField struct {
	typ       reflect.Type
	index     []int
	depth     int
	tagged    bool
	ambiguous bool
}

var structFieldCache sync.Map // map[reflect.Type]map[string]schemaField

func cachedStructFields(typ reflect.Type) map[string]schemaField {
	if fields, ok := structFieldCache.Load(typ); ok {
		return fields.(map[string]schemaField)
	}
	// Cache only a complete top-level schema. Recursive embedded traversal
	// stays in structFields so ancestor-dependent cycle handling is preserved.
	fields := structFields(typ, make(map[reflect.Type]bool))
	actual, _ := structFieldCache.LoadOrStore(typ, fields)
	return actual.(map[string]schemaField)
}

func structFields(typ reflect.Type, ancestors map[reflect.Type]bool) map[string]schemaField {
	fields := make(map[string]schemaField)
	if ancestors[typ] {
		return fields
	}
	ancestors[typ] = true
	defer delete(ancestors, typ)
	add := func(name string, candidate schemaField) {
		previous, exists := fields[name]
		if !exists || candidate.depth < previous.depth ||
			(candidate.depth == previous.depth && candidate.tagged && !previous.tagged) {
			fields[name] = candidate
		} else if candidate.depth == previous.depth && candidate.tagged == previous.tagged {
			previous.ambiguous = true
			fields[name] = previous
		}
	}
	for i := range typ.NumField() {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag == "-" || (!field.IsExported() && !field.Anonymous) {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if !validFieldTag(name) {
			name = ""
		}
		embedded := field.Type
		if embedded.Kind() == reflect.Pointer {
			embedded = embedded.Elem()
		}
		if name == "" && field.Anonymous && embedded.Kind() == reflect.Struct {
			for childName, child := range structFields(embedded, ancestors) {
				child.depth++
				child.index = append([]int{i}, child.index...)
				add(childName, child)
			}
			continue
		}
		if !field.IsExported() && embedded.Kind() != reflect.Struct {
			continue
		}
		tagged := name != ""
		if !tagged {
			name = field.Name
		}
		add(name, schemaField{typ: field.Type, index: []int{i}, tagged: tagged})
	}
	return fields
}

// schemaHazards records schema shapes whose bindings differ between the
// classic encoding/json decoder and the json v2-backed decoder Go 1.27 links
// by default: a folded name that resolves at more than one embedding depth
// (classic picks field-index order, v2 picks the shallowest field even over an
// exact match), and a json tag name outside the tag grammar (classic falls
// back to the Go field name, v2 does not), a tag option outside the documented
// set (classic ignores it, v2 may honor it), and an anonymous field typed from
// the encoding/json packages (v2 treats jsontext.Value as an unknown-member
// fallback). The walker cannot match both decoders, so it refuses these shapes
// instead of guessing a binding.
type schemaHazards struct {
	unsupported bool
	depthFolds  map[string]bool
}

var schemaHazardCache sync.Map // map[reflect.Type]schemaHazards

func cachedSchemaHazards(typ reflect.Type) schemaHazards {
	if hazards, ok := schemaHazardCache.Load(typ); ok {
		return hazards.(schemaHazards)
	}
	hazards := schemaHazards{unsupported: hasDecoderDependentField(typ, make(map[reflect.Type]bool))}
	depths := make(map[string]int)
	for name, field := range cachedStructFields(typ) {
		if field.ambiguous {
			continue
		}
		folded := FoldKey(name)
		depth, seen := depths[folded]
		if !seen {
			depths[folded] = field.depth
			continue
		}
		if depth != field.depth {
			if hazards.depthFolds == nil {
				hazards.depthFolds = make(map[string]bool)
			}
			hazards.depthFolds[folded] = true
		}
	}
	actual, _ := schemaHazardCache.LoadOrStore(typ, hazards)
	return actual.(schemaHazards)
}

// hasDecoderDependentField reports, on typ or on any struct it embeds without a
// name, a non-empty json tag name that fails the tag grammar, a tag option
// outside the documented set, or an anonymous field typed from the
// encoding/json packages.
func hasDecoderDependentField(typ reflect.Type, ancestors map[reflect.Type]bool) bool {
	if ancestors[typ] {
		return false
	}
	ancestors[typ] = true
	defer delete(ancestors, typ)
	for i := range typ.NumField() {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag == "-" || (!field.IsExported() && !field.Anonymous) {
			continue
		}
		name, options, _ := strings.Cut(tag, ",")
		if (name != "" && !validFieldTag(name)) || hasUndocumentedTagOption(options) {
			return true
		}
		embedded := indirectType(field.Type)
		if field.Anonymous && strings.HasPrefix(embedded.PkgPath(), "encoding/json/") {
			return true
		}
		if name == "" && field.Anonymous && embedded.Kind() == reflect.Struct && hasDecoderDependentField(embedded, ancestors) {
			return true
		}
	}
	return false
}

// decodesItselfUnderV2 reports a type with an UnmarshalJSONFrom method. The
// json v2-backed decoder calls it before UnmarshalJSON, while the classic
// decoder never calls it, so the two decoders can hand an object's members to
// different code whatever the type's kind. json.Number is the one exception:
// Go 1.27 gives it the method, but it decodes only a JSON number under both
// decoders. The method is found by name so this package does not depend on
// the v2 packages being linked.
func decodesItselfUnderV2(typ reflect.Type) bool {
	if typ == jsonNumberType {
		return false
	}
	_, ok := reflect.PointerTo(typ).MethodByName("UnmarshalJSONFrom")
	return ok
}

var jsonNumberType = reflect.TypeFor[json.Number]()

// hasUndocumentedTagOption reports a tag option other than the three the
// encoding/json package documents: omitempty, omitzero and string. The classic
// decoder ignores any other option, while the json v2-backed decoder honors
// options such as case:strict and embed that change which field a key binds,
// so a schema using one has no single binding the walker can vouch for.
func hasUndocumentedTagOption(options string) bool {
	for _, option := range strings.Split(options, ",") {
		switch option {
		case "", "omitempty", "omitzero", "string":
		default:
			return true
		}
	}
	return false
}

// validFieldTag follows encoding/json's tag-name grammar. Invalid names fall
// back to the Go field name; only an entire "-" tag suppresses a field.
func validFieldTag(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", r) && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
