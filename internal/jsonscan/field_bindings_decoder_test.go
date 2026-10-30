// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonscan

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

type diffInner struct {
	Shared string `json:"shared"`
	Deep   string
}

type diffInner2 struct {
	Deep  string
	Other string `json:"other_name"`
}

type diffSchema struct {
	diffInner
	Key    string `json:"key"`
	KEY    string `json:"KEY"`
	Kelvin string `json:"kind"`
	Skip   string `json:"-"`
	Sigma  string `json:"σtate"`
	Plain  string
	Under  string `json:"user_id"`
	Long   string `json:"session"`
}

type diffAmbig struct {
	diffInner
	diffInner2
	Top string `json:"top"`
}

// goBinding returns the dotted Go field path encoding/json assigns for key.
func goBinding(t *testing.T, target any, key string) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{key: "\x00marker"})
	v := reflect.New(reflect.TypeOf(target).Elem())
	if err := json.Unmarshal(raw, v.Interface()); err != nil {
		t.Fatalf("unmarshal %q: %v", key, err)
	}
	var found []string
	var walk func(reflect.Value, string)
	walk = func(rv reflect.Value, prefix string) {
		for i := range rv.NumField() {
			f := rv.Type().Field(i)
			fv := rv.Field(i)
			if f.Type.Kind() == reflect.Struct {
				walk(fv, prefix+f.Name+".")
				continue
			}
			if fv.Kind() == reflect.String && fv.String() == "\x00marker" {
				found = append(found, prefix+f.Name)
			}
		}
	}
	walk(v.Elem(), "")
	if len(found) > 1 {
		t.Fatalf("multiple bindings for %q: %v", key, found)
	}
	if len(found) == 0 {
		return ""
	}
	return found[0]
}

func walkerBinding(target any, key string) string {
	typ := reflect.TypeOf(target).Elem()
	_, field, ok := boundField(cachedStructFields(typ), key)
	if !ok {
		return ""
	}
	path := ""
	cur := typ
	for _, i := range field.index {
		f := cur.Field(i)
		if f.Type.Kind() == reflect.Struct && f.Anonymous {
			path += f.Name + "."
			cur = f.Type
			continue
		}
		path += f.Name
	}
	return path
}

// foldBits is a fixed-seed xorshift64 source (Marsaglia, "Xorshift RNGs",
// J. Stat. Softw. 8(14), 2003, shift triple 13/7/17). The corpus only needs a
// reproducible spread of case folds, not statistical or cryptographic quality.
type foldBits struct{ x uint64 }

func (b *foldBits) next() bool {
	b.x ^= b.x << 13
	b.x ^= b.x >> 7
	b.x ^= b.x << 17
	return b.x&1 == 1
}

// dashSchema pairs an ignored field with one encoding/json names "-" via the
// `-,` tag. Static analysis rejects that tag as a literal, so the type is built
// at run time.
func dashSchema() any {
	str := reflect.TypeFor[string]()
	return reflect.New(reflect.StructOf([]reflect.StructField{
		{Name: "Skip", Type: str, Tag: `json:"-"`},
		{Name: "Dash", Type: str, Tag: `json:"-,"`},
		{Name: "Plain", Type: str},
	})).Interface()
}

func variants(name string, rng *foldBits) []string {
	out := []string{name, strings.ToUpper(name), strings.ToLower(name)}
	subs := map[rune][]string{'k': {"K", "K"}, 'K': {"K", "k"}, 's': {"ſ", "S"}, 'S': {"ſ"}, 'σ': {"Σ", "ς"}, 'i': {"I", "İ", "ı"}, '_': {"", "-"}}
	runes := []rune(name)
	for i, r := range runes {
		for _, s := range subs[r] {
			out = append(out, string(runes[:i])+s+string(runes[i+1:]))
		}
		if unicode.IsLetter(r) {
			out = append(out, string(runes[:i])+string(unicode.SimpleFold(r))+string(runes[i+1:]))
		}
	}
	for range 40 {
		b := []rune(name)
		for j := range b {
			if rng.next() {
				b[j] = unicode.SimpleFold(b[j])
			}
		}
		out = append(out, string(b))
	}
	return out
}

// The walker must resolve every key to the field encoding/json binds, including
// Unicode simple folds, delimiters, precedence and embedded-field dominance.
// A key the decoder binds but the walker misses would hide a collision.
func TestFieldBindingMatchesDecoder(t *testing.T) {
	rng := &foldBits{x: 1}
	names := []string{"shared", "Deep", "key", "KEY", "kind", "Skip", "-", "σtate", "Plain", "user_id", "session", "other_name", "top", "Key", "Dash"}
	checked := 0
	for _, target := range []any{new(diffSchema), new(diffAmbig), dashSchema()} {
		for _, name := range names {
			for _, key := range variants(name, rng) {
				g, w := goBinding(t, target, key), walkerBinding(target, key)
				checked++
				if g != w {
					t.Errorf("%T key %q (%+q): encoding/json binds %q, walker resolves %q", target, key, key, g, w)
				}
			}
		}
	}
	if checked < 1000 {
		t.Fatalf("only %d keys checked", checked)
	}
}
