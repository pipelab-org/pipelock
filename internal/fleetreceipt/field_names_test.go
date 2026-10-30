// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fleetreceipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func TestEnvelopeFieldNames(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(pub)
	envelope, err := SignStatement(testStatement(), id, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{id: pub}
	if result, err := Verify(raw, keys); err != nil || !result.Trusted {
		t.Fatalf("canonical producer: %v", err)
	}
	for _, field := range []string{"payload", "signatures", "keyid"} {
		changed := strings.Replace(string(raw), `"`+field+`":`, `"`+strings.ToUpper(field[:1])+field[1:]+`":`, 1)
		if changed == string(raw) {
			t.Fatalf("missing field %s", field)
		}
		if _, err := Verify([]byte(changed), keys); err == nil {
			t.Fatalf("accepted noncanonical %s", field)
		}
	}
}
