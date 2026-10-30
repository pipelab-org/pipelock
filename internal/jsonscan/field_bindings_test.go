// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonscan

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

type (
	bindingLeaf struct {
		Value string `json:"value"`
	}
	bindingRequest struct {
		Item   *bindingLeaf            `json:"item"`
		Items  []bindingLeaf           `json:"items"`
		Array  [1]bindingLeaf          `json:"array"`
		Values map[string]*bindingLeaf `json:"values"`
		Data   map[string]any          `json:"data"`
		Raw    json.RawMessage         `json:"raw"`
	}
)

func TestFieldBindingPolicies(t *testing.T) {
	for _, tc := range []struct {
		name, raw        string
		collision, alias bool
	}{
		{"canonical", `{"item":{"value":"ok"}}`, false, false},
		{"lone alias", `{"Item":{"Value":"ok"}}`, false, true},
		{"two aliases", `{"Item":{},"ITEM":{}}`, true, true},
		{"canonical and alias", `{"item":{},"Item":{}}`, true, true},
		{"reversed", `{"Item":{},"item":{}}`, true, true},
		{"escaped name", `{"item":{},"\u0069tem":{}}`, true, true},
		{"nested", `{"item":{"value":"one","VALUE":"two"}}`, true, true},
		{"slice", `{"items":[{"value":"one","Value":"two"}]}`, true, true},
		{"array", `{"array":[{"value":"one","VALUE":"two"}]}`, true, true},
		{"typed map", `{"values":{"a":{"value":"one","VALUE":"two"}}}`, true, true},
		{"case distinct map keys", `{"values":{"a":{"value":"one"},"A":{"value":"two"}}}`, false, false},
		{"application data", `{"data":{"key":1,"KEY":2}}`, false, false},
		{"raw custom boundary", `{"raw":{"value":1,"VALUE":2}}`, false, false},
		{"unknown field", `{"future":1,"FUTURE":2}`, false, false},
		{"null", `{"item":null}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := bindingRequest{Item: &bindingLeaf{Value: "retained"}}
			raw := []byte(tc.raw)
			err := RejectDuplicateFields(raw, &target)
			if (err != nil) != tc.collision {
				t.Fatalf("request collision=%v: %v", tc.collision, err)
			}
			if tc.collision && !errors.Is(err, ErrDuplicateKey) {
				t.Fatalf("duplicate sentinel: %v", err)
			}
			if got := RejectNonCanonicalFields(raw, &target); (got != nil) != tc.alias {
				t.Fatalf("evidence alias=%v: %v", tc.alias, got)
			}
			if target.Item.Value != "retained" {
				t.Fatal("guard mutated destination")
			}
		})
	}
}

func TestFieldBindingMixedPolicy(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		reject bool
	}{
		{`{"Item":{"value":"ok"},"Data":{"a":1,"A":2}}`, false},
		{`{"Item":{"Value":"ok"}}`, true},
		{`{"Values":{"a":{"Value":"ok"}}}`, true},
		{`{"Items":[{"Value":"ok"}]}`, true},
	} {
		if err := RejectDuplicateFields([]byte(tc.raw), new(bindingRequest), new(bindingLeaf)); (err != nil) != tc.reject {
			t.Errorf("%s: %v", tc.raw, err)
		}
	}
}

func TestFieldBindingResolution(t *testing.T) {
	type first struct {
		Value string
	}
	type second struct {
		Value string
	}
	type ambiguous struct {
		first
		second
	}
	type embedded struct {
		first
		Value string
	}
	type distinct struct {
		Lower bindingLeaf `json:"key"`
		Upper string      `json:"KEY"`
	}
	type reversed struct {
		Upper string      `json:"KEY"`
		Lower bindingLeaf `json:"key"`
	}
	for _, tc := range []struct {
		name, raw string
		target    any
		reject    bool
	}{
		{"ambiguous ignored", `{"value":"one","VALUE":"two"}`, new(ambiguous), false},
		{"shadow", `{"value":"one","VALUE":"two"}`, new(embedded), true},
		{"exact priority", `{"key":{"value":"one"},"KEY":"two"}`, new(distinct), false},
		{"first folded match", `{"key":{"value":"one"},"Key":{}}`, new(distinct), true},
		{"index order", `{"KEY":"one","Key":"two"}`, new(reversed), true},
		{"index distinct", `{"key":{"value":"one"},"Key":"two"}`, new(reversed), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := RejectDuplicateFields([]byte(tc.raw), tc.target); (err != nil) != tc.reject {
				t.Fatalf("reject=%v: %v", tc.reject, err)
			}
			if err := json.Unmarshal([]byte(tc.raw), tc.target); err != nil {
				t.Fatalf("decoder control: %v", err)
			}
		})
	}
	if err := RejectStructAliases([]byte(`{}`), nil); err != nil {
		t.Fatal(err)
	}
	if err := RejectDuplicateFields([]byte(`{}`), nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := RejectStructAliases([]byte(`[]`), reflect.TypeFor[bindingLeaf]()); err != nil {
		t.Fatal(err)
	}
}

func TestFieldBindingTagGrammar(t *testing.T) {
	// encoding/json accepts both tags below, but static analysis rejects them
	// as literals, so these fixtures are built at run time.
	fixture := func(tag reflect.StructTag) any {
		return reflect.New(reflect.StructOf([]reflect.StructField{
			{Name: "Value", Type: reflect.TypeFor[string](), Tag: tag},
		})).Interface()
	}
	invalid, dash := fixture(`json:"bad\\name"`), fixture(`json:"-,omitempty"`)
	for _, tc := range []struct {
		raw    string
		target any
		reject bool
	}{
		// Decoders disagree on what an invalid tag name binds, so no input is
		// vouched for: the classic decoder falls back to "Value", Go 1.27's
		// default decoder does not.
		{`{"Value":"ok"}`, invalid, true},
		{`{"bad":"ok","BAD":"other"}`, invalid, true},
		{`{"Value":"ok","value":"other"}`, invalid, true},
		{`{"-":"one","\u002d":"two"}`, dash, true},
	} {
		if err := RejectDuplicateFields([]byte(tc.raw), tc.target); (err != nil) != tc.reject {
			t.Fatalf("tag policy: %v", err)
		}
	}
}

type depthLeaf struct {
	Key string
}

type depthSchema struct {
	depthLeaf
	Upper string `json:"KEY"`
	Other string `json:"other"`
}

// A folded name that resolves at two embedding depths binds differently under
// the classic and Go 1.27 default decoders, so every key in that group is
// refused, including exact matches; unrelated keys keep working.
func TestFieldBindingRefusesDecoderDependentDepths(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		reject bool
	}{
		{`{"other":"ok"}`, false},
		{`{"KEY":"one"}`, true},
		{`{"Key":"one"}`, true},
		{`{"KEY":"one","Key":"two"}`, true},
	} {
		err := RejectDuplicateFields([]byte(tc.raw), new(depthSchema))
		if (err != nil) != tc.reject || (err != nil && !errors.Is(err, ErrDuplicateKey)) {
			t.Fatalf("%s: reject=%v: %v", tc.raw, tc.reject, err)
		}
	}
}

// Options outside omitempty, omitzero and string are ignored by the classic
// decoder but can change bindings under the json v2-backed decoder, so the
// walker refuses schemas that use them; documented options keep working.
func TestFieldBindingRefusesUndocumentedTagOptions(t *testing.T) {
	str := reflect.TypeFor[string]()
	fixture := func(fields ...reflect.StructField) any {
		return reflect.New(reflect.StructOf(fields)).Interface()
	}
	inner := reflect.StructOf([]reflect.StructField{{Name: "B", Type: str}})
	for _, tc := range []struct {
		name   string
		target any
		raw    string
		reject bool
	}{
		{"documented", fixture(reflect.StructField{Name: "ID", Type: str, Tag: `json:"id,omitempty,omitzero"`}), `{"id":"one"}`, false},
		{"string option", fixture(reflect.StructField{Name: "N", Type: reflect.TypeFor[int](), Tag: `json:"n,string"`}), `{"n":"1"}`, false},
		{"case strict", fixture(reflect.StructField{Name: "ID", Type: str, Tag: `json:",case:strict"`}), `{"ID":"one"}`, true},
		{"embed", fixture(reflect.StructField{Name: "Inner", Type: inner, Tag: `json:",embed"`}), `{"B":"one"}`, true},
	} {
		err := RejectDuplicateFields([]byte(tc.raw), tc.target)
		if (err != nil) != tc.reject || (err != nil && !errors.Is(err, ErrDuplicateKey)) {
			t.Fatalf("%s: reject=%v: %v", tc.name, tc.reject, err)
		}
	}
}

type selfDecoding struct {
	ID string
}

// UnmarshalJSONFrom only needs to exist: the guard detects the method by name.
func (*selfDecoding) UnmarshalJSONFrom(any) error { return nil }

// selfDecodingList shows the refusal does not depend on the type's kind.
type selfDecodingList []string

func (*selfDecodingList) UnmarshalJSONFrom(any) error { return nil }

// A type with UnmarshalJSONFrom is decoded by different code under the classic
// and json v2-backed decoders, so the guard refuses it at the top level and
// nested inside a typed field.
func TestFieldBindingRefusesV2SelfDecodingTypes(t *testing.T) {
	type wrapper struct {
		Inner selfDecoding `json:"inner"`
		Other string       `json:"other"`
	}
	for _, tc := range []struct {
		name   string
		raw    string
		target any
	}{
		{"top level", `{"ID":"one"}`, new(selfDecoding)},
		{"nested", `{"inner":{"ID":"one"}}`, new(wrapper)},
		{"slice kind", `{"left":"one","LEFT":"two"}`, new(selfDecodingList)},
	} {
		if err := RejectDuplicateFields([]byte(tc.raw), tc.target); !errors.Is(err, ErrDuplicateKey) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	// A scalar binds no object members, so a number field stays accepted even
	// where json.Number carries UnmarshalJSONFrom.
	var number struct {
		Value json.Number `json:"value"`
	}
	if err := RejectStructAliases([]byte(`{"value":12}`), reflect.TypeOf(number)); err != nil {
		t.Fatalf("number field refused: %v", err)
	}
}

func TestFieldBindingValidatedNumbers(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		reject bool
	}{
		{`{"item":{"value":"ok"},"raw":[1e10001]}`, false},
		{`{"item":{"value":"one","Value":"two"},"raw":[1e10001]}`, true},
	} {
		raw := []byte(tc.raw)
		if err := ValidateKeys(raw, MaxNestingDepth); err != nil {
			t.Fatalf("numeric validation control: %v", err)
		}
		if err := RejectDuplicateFieldsInValidatedJSON(raw, new(bindingRequest)); (err != nil) != tc.reject {
			t.Fatalf("binding policy: %v", err)
		}
	}
}

type signedBindingLeaf bindingLeaf

func (signedBindingLeaf) Signed() {}

func TestFieldBindingInterfaceSchema(t *testing.T) {
	type signed interface{ Signed() }
	type request struct {
		Plain  bindingLeaf        `json:"plain"`
		Signed *signedBindingLeaf `json:"signed"`
	}
	for _, tc := range []struct {
		raw    string
		reject bool
	}{
		{`{"Plain":{"Value":"ok"},"Signed":{"value":"ok"}}`, false},
		{`{"signed":{"Value":"ok"}}`, true},
		{`{"plain":{"value":"one","Value":"two"}}`, true},
	} {
		if err := RejectDuplicateFields([]byte(tc.raw), new(request), (*signed)(nil)); (err != nil) != tc.reject {
			t.Errorf("%s: %v", tc.raw, err)
		}
	}
	if err := RejectDuplicateFields([]byte(`{"Value":"ok"}`), new(signedBindingLeaf), (*signed)(nil)); err == nil {
		t.Error("top-level implementation accepted a lone alias")
	}
}
