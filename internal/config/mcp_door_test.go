// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func validDoor(t *testing.T) MCPDoor {
	t.Helper()
	return MCPDoor{
		Enabled: true, Issuer: "https://issuer.example", Audience: "https://resource.example/mcp",
		Mode: MCPDoorJWT, JWKSFile: filepath.Join(t.TempDir(), "keys.json"),
		Enrollments:    []MCPDoorEnrollment{{Subject: "subject", ClientID: "client"}},
		RequiredScopes: []string{"tools:read"},
	}
}

func TestMCPDoorDefaults(t *testing.T) {
	for _, raw := range []string{"", "mcp_door: null", "mcp_door:", "mcp_door: {}", "mcp_door:\n  enabled: null", "mcp_door:\n  enabled:", "mcp_door:\n  enabled: false"} {
		t.Run(raw, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MCPDoor.Enabled {
				t.Fatal("door enabled by default")
			}
		})
	}
	if _, err := LoadBytes([]byte("mcp_door:\n  enabled: true")); err == nil {
		t.Fatal("incomplete enabled profile accepted")
	}
	raw := fmt.Sprintf("mcp_door:\n  enabled: true\n  issuer: https://issuer.example\n  audience: https://resource.example/mcp\n  mode: jwt\n  jwks_file: %q\n", validDoor(t).JWKSFile)
	cfg, err := LoadBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.MCPDoor.Enabled {
		t.Fatal("explicit true not applied")
	}
	if Defaults().MCPDoor.Enabled {
		t.Fatal("programmatic default changed")
	}
}

func TestMCPDoorValidation(t *testing.T) {
	for _, tt := range []struct {
		name   string
		modify func(*MCPDoor)
	}{
		{"issuer", func(d *MCPDoor) { d.Issuer = "" }},
		{"audience", func(d *MCPDoor) { d.Audience = "" }},
		{"http issuer", func(d *MCPDoor) { d.Issuer = "http://issuer.example" }},
		{"query audience", func(d *MCPDoor) { d.Audience += "?token=x" }},
		{"fragment audience", func(d *MCPDoor) { d.Audience += "#fragment" }},
		{"userinfo", func(d *MCPDoor) { d.Issuer = "https://user:password@issuer.example" }},
		{"mode", func(d *MCPDoor) { d.Mode = "auto" }},
		{"missing keys", func(d *MCPDoor) { d.JWKSFile = "" }},
		{"relative keys", func(d *MCPDoor) { d.JWKSFile = "keys.json" }},
		{"mixed", func(d *MCPDoor) { d.IntrospectionURL = "https://issuer.example/introspect" }},
		{"introspection endpoint", func(d *MCPDoor) {
			d.Mode = MCPDoorIntrospection
			d.JWKSFile = ""
			d.ClientID = "verifier"
			d.ClientSecretFile = validDoor(t).JWKSFile
		}},
		{"introspection credential", func(d *MCPDoor) {
			d.Mode = MCPDoorIntrospection
			d.JWKSFile = ""
			d.IntrospectionURL = "https://issuer.example/introspect"
		}},
		{"introspection mixed", func(d *MCPDoor) {
			d.Mode = MCPDoorIntrospection
			d.IntrospectionURL = "https://issuer.example/introspect"
			d.ClientID = "verifier"
			d.ClientSecretFile = d.JWKSFile
		}},
		{"timeout negative", func(d *MCPDoor) { d.TimeoutSeconds = -1 }},
		{"timeout overflow", func(d *MCPDoor) { d.TimeoutSeconds = int(maxConfigDurationSeconds) + 1 }},
		{"empty subject", func(d *MCPDoor) { d.Enrollments[0].Subject = "" }},
		{"empty client", func(d *MCPDoor) { d.Enrollments[0].ClientID = "" }},
		{"whitespace subject", func(d *MCPDoor) { d.Enrollments[0].Subject = " subject" }},
		{"duplicate enrollment", func(d *MCPDoor) { d.Enrollments = append(d.Enrollments, d.Enrollments[0]) }},
		{"empty scope", func(d *MCPDoor) { d.RequiredScopes = []string{""} }},
		{"invalid scope", func(d *MCPDoor) { d.RequiredScopes = []string{"read write"} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := validDoor(t)
			tt.modify(&d)
			if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "mcp_door") {
				t.Fatalf("validation = %v", err)
			}
		})
	}
	d := validDoor(t)
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	d.Mode = MCPDoorIntrospection
	d.JWKSFile = ""
	d.IntrospectionURL = "https://issuer.example/introspect"
	d.ClientID = "verifier"
	d.ClientSecretFile = validDoor(t).JWKSFile
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	d.Enrollments = nil
	if err := d.Validate(); err != nil {
		t.Fatal("deny-all enrollment should be valid")
	}
}

func TestMCPDoorCloneAndHash(t *testing.T) {
	c := Defaults()
	c.MCPDoor = validDoor(t)
	clone := c.Clone()
	if !c.MCPDoor.Equal(clone.MCPDoor) {
		t.Fatal("clone changed door")
	}
	clone.MCPDoor.Enrollments[0].Subject = "other"
	clone.MCPDoor.RequiredScopes[0] = "tools:write"
	if c.MCPDoor.Enrollments[0].Subject != "subject" || c.MCPDoor.RequiredScopes[0] != "tools:read" {
		t.Fatal("clone aliases door state")
	}
	if c.CanonicalPolicyHash() == clone.CanonicalPolicyHash() {
		t.Fatal("door authorization omitted from policy hash")
	}
}
