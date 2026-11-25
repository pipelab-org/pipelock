// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestTLSCRLURLValidation(t *testing.T) {
	for _, tc := range []struct {
		yaml  string
		valid bool
	}{
		{"{}", true},
		{"crl_url:", true},
		{"crl_url: null", true},
		{`crl_url: ""`, true},
		{`crl_url: "off"`, true},
		{"crl_url: http://127.0.0.1:8888/.well-known/pipelock/ca.crl", true},
		{"crl_url: http://crl.vendor.example/ca.crl", true},
		{"crl_url: https://crl.vendor.example/ca.crl", false},
		{"crl_url: false", false},
		{"crl_url: true", false},
		{"crl_url: /relative", false},
		{"crl_url: http:///ca.crl", false},
		{"crl_url: http://user:password@crl.vendor.example/ca.crl", false},
		{"crl_url: http://crl.vendor.example/ca.crl#fragment", false},
		{`crl_url: "http://crl.vendor.example/ca.crl#"`, false},
		{"crl_url: http://crl.vendor.example/café.crl", false},
		{`crl_url: " http://crl.vendor.example/ca.crl"`, false},
	} {
		t.Run(tc.yaml, func(t *testing.T) {
			_, err := LoadBytes([]byte("tls_interception:\n  " + tc.yaml + "\n"))
			if (err == nil) != tc.valid {
				t.Fatalf("err = %v, valid = %v", err, tc.valid)
			}
		})
	}
}

func TestTLSCRLPolicyHash(t *testing.T) {
	original := Defaults().CanonicalPolicyHash()
	for _, raw := range []string{"off", "http://crl.vendor.example/ca.crl"} {
		cfg := Defaults()
		cfg.TLSInterception.CRLURL = raw
		if cfg.CanonicalPolicyHash() == original {
			t.Fatal("explicit CRL setting missing from policy identity")
		}
	}
}
