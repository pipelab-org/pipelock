// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

// MCP door verification modes.
const (
	MCPDoorJWT           = "jwt"
	MCPDoorIntrospection = "introspection"
)

// MCPDoor verifies externally issued access tokens on the MCP HTTP listener.
// Its zero value preserves the existing listener authentication behavior.
type MCPDoor struct {
	Enabled          bool                `yaml:"enabled"`
	Issuer           string              `yaml:"issuer"`
	Audience         string              `yaml:"audience"`
	Mode             string              `yaml:"mode"`
	JWKSFile         string              `yaml:"jwks_file"`
	IntrospectionURL string              `yaml:"introspection_url"`
	ClientID         string              `yaml:"client_id"`
	ClientSecretFile string              `yaml:"client_secret_file"`
	TimeoutSeconds   int                 `yaml:"timeout_seconds"`
	Enrollments      []MCPDoorEnrollment `yaml:"enrollments"`
	RequiredScopes   []string            `yaml:"required_scopes"`
}

// MCPDoorEnrollment admits precisely one verified subject/client pair.
type MCPDoorEnrollment struct {
	Subject  string `yaml:"subject"`
	ClientID string `yaml:"client_id"`
}

// Clone returns a door configuration with independently owned slices.
func (d MCPDoor) Clone() MCPDoor {
	d.Enrollments = slices.Clone(d.Enrollments)
	d.RequiredScopes = slices.Clone(d.RequiredScopes)
	return d
}

// Equal reports whether a restart-only verifier configuration is unchanged.
func (d MCPDoor) Equal(other MCPDoor) bool { return reflect.DeepEqual(d, other) }

// Validate checks the operator-pinned verifier profile, without reading files.
func (d MCPDoor) Validate() error {
	if !d.Enabled {
		return nil
	}
	for _, field := range []struct{ name, value string }{
		{"issuer", d.Issuer}, {"audience", d.Audience},
	} {
		if !mcpDoorHTTPSURL(field.value) {
			return fmt.Errorf("mcp_door.%s requires an absolute HTTPS URL without credentials, query or fragment", field.name)
		}
	}
	if d.TimeoutSeconds < 0 || int64(d.TimeoutSeconds) > maxConfigDurationSeconds {
		return fmt.Errorf("mcp_door.timeout_seconds must be between 0 and %d", maxConfigDurationSeconds)
	}
	switch d.Mode {
	case MCPDoorJWT:
		if !filepath.IsAbs(d.JWKSFile) {
			return fmt.Errorf("mcp_door.jwks_file requires an absolute pinned public JWKS file")
		}
		if d.IntrospectionURL != "" || d.ClientID != "" || d.ClientSecretFile != "" {
			return fmt.Errorf("mcp_door JWT mode cannot configure introspection credentials")
		}
	case MCPDoorIntrospection:
		if !mcpDoorHTTPSURL(d.IntrospectionURL) || !mcpDoorIdentifier(d.ClientID) || !filepath.IsAbs(d.ClientSecretFile) {
			return fmt.Errorf("mcp_door introspection requires an HTTPS introspection_url, client_id and absolute client_secret_file")
		}
		if d.JWKSFile != "" {
			return fmt.Errorf("mcp_door introspection mode cannot configure jwks_file")
		}
	default:
		return fmt.Errorf("mcp_door.mode must be jwt or introspection")
	}
	seen := make(map[MCPDoorEnrollment]bool)
	for _, e := range d.Enrollments {
		if !mcpDoorIdentifier(e.Subject) || !mcpDoorIdentifier(e.ClientID) || seen[e] {
			return fmt.Errorf("mcp_door.enrollments requires distinct, nonempty subject/client_id pairs")
		}
		seen[e] = true
	}
	for _, scope := range d.RequiredScopes {
		if !ValidMCPDoorScope(scope) {
			return fmt.Errorf("mcp_door.required_scopes contains an invalid scope")
		}
	}
	return nil
}

func mcpDoorIdentifier(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

func mcpDoorHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" &&
		u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && strings.TrimSpace(raw) == raw && u.String() == raw
}

// ValidMCPDoorScope checks one scope-token using RFC 6749 section 3.3's ABNF.
func ValidMCPDoorScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, c := range scope {
		valid := c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e)
		if !valid {
			return false
		}
	}
	return true
}
