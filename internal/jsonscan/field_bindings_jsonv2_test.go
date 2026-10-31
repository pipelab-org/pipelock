// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build go1.27 && goexperiment.jsonv2

package jsonscan

import (
	"encoding/json/jsontext"
	"errors"
	"testing"
)

// Under the json v2-backed decoder an anonymous jsontext.Value collects
// unknown members, which the classic decoder treats as an ordinary field, so
// the guard refuses the schema.
func TestFieldBindingRefusesAnonymousJSONTextValue(t *testing.T) {
	type fallback struct {
		ID string `json:"id"`
		jsontext.Value
	}
	if err := RejectDuplicateFields([]byte(`{"id":"one"}`), new(fallback)); !errors.Is(err, ErrDuplicateKey) {
		t.Fatal(err)
	}
}
