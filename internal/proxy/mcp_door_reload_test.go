// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestMCPDoorReload(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "off", true: "on"}[enabled], func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.MCPDoor = config.MCPDoor{Enabled: enabled, Issuer: "https://issuer.example", Audience: "https://resource.example/mcp", Mode: config.MCPDoorJWT, JWKSFile: "/keys.json"}
			p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			for _, tt := range []struct {
				name   string
				modify func(*config.MCPDoor)
			}{
				{"enabled", func(d *config.MCPDoor) { d.Enabled = !d.Enabled }},
				{"issuer", func(d *config.MCPDoor) { d.Issuer = "https://other.example" }},
				{"audience", func(d *config.MCPDoor) { d.Audience = "https://other.example/mcp" }},
				{"key", func(d *config.MCPDoor) { d.JWKSFile = "/other.json" }},
				{"enrollment", func(d *config.MCPDoor) {
					d.Enrollments = []config.MCPDoorEnrollment{{Subject: "other", ClientID: "client"}}
				}},
				{"scope", func(d *config.MCPDoor) { d.RequiredScopes = []string{"tools:write"} }},
			} {
				t.Run(tt.name, func(t *testing.T) {
					next := cfg.Clone()
					tt.modify(&next.MCPDoor)
					if p.Reload(next, scanner.MustNew(next)) {
						t.Fatal("door change accepted without restart")
					}
					if p.CurrentConfig() != cfg {
						t.Fatal("rejected reload replaced active config")
					}
				})
			}
			next := cfg.Clone()
			next.ExplainBlocks = new(true)
			if !p.Reload(next, scanner.MustNew(next)) {
				t.Fatal("unrelated reload refused")
			}
			if !p.CurrentConfig().MCPDoor.Equal(cfg.MCPDoor) {
				t.Fatal("unrelated reload altered door")
			}
		})
	}
}
