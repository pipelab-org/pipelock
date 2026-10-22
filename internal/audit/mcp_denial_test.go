// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/emit"
)

func TestMCPBlockedProjectionFormats(t *testing.T) {
	for _, method := range []string{"MCP", "CEE", "GET"} {
		for _, mcp := range []bool{false, true} {
			for _, local := range []bool{false, true} {
				var output bytes.Buffer
				logger, err := NewWithStream("json", "stdout", "", true, local, &output)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)
				sink := &collectingSink{}
				logger.SetEmitter(emit.NewEmitter("fixture", sink))
				ctx := NewMethodLogContext(method)
				if mcp {
					ctx, err = NewMCPLogContext(method, "mcp-input", "")
					if err != nil {
						t.Fatal(err)
					}
					ctx = ctx.WithMCPRoute("mcp_stdio", "input")
					logger.LogMCPBlocked(ctx, "cross_request_fragment_capacity", "capacity exhausted", BlockDetail{Class: BlockClassInfrastructureError})
				} else {
					logger.LogBlockedDetail(ctx, "ssrf", "refused", BlockDetail{Class: BlockClassInfrastructureError})
				}
				event := sink.onlyEvent(t)
				if _, ok := event.Fields["block_class"]; ok != mcp {
					t.Fatalf("method=%s mcp=%v fields=%v", method, mcp, event.Fields)
				}
				if _, ok := event.Fields["protocol"]; ok != mcp {
					t.Fatalf("incorrect protocol: %v", event.Fields)
				}
				if local && strings.Contains(output.String(), `"block_class"`) != mcp {
					t.Fatal(output.String())
				}
				if !local && output.Len() != 0 {
					t.Fatal("local suppression ignored")
				}
				encoded, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), `"block_class"`) != mcp {
					t.Fatal(string(encoded))
				}
				cef := emit.FormatCEFEvent(event, "fixture")
				if strings.Contains(cef, "pipelockBlockClass=infrastructure_error") != mcp {
					t.Fatal(cef)
				}
				ocsf := emit.FormatOCSFEvent(event, "fixture")
				if strings.Contains(ocsf, `"block_class":"infrastructure_error"`) != mcp {
					t.Fatal(ocsf)
				}
			}
		}
	}
}
