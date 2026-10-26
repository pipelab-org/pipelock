// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

// mcpBridgeHeaders joins the listener's contract acquisition/serialization and
// the bridge's per-process tool baseline. Only the contract portion of state is
// used: this bridge's fixed upstream credentials scope its lifetime.
type mcpBridgeHeaders struct {
	client *transport.HTTPClient
	state  *mcpListenerClientState
	opts   MCPProxyOpts
	log    io.Writer
}

func (b *mcpBridgeHeaders) version(msg []byte) string {
	// A modern per-request version takes precedence over a legacy handshake,
	// matching the listener's request metadata contract. Otherwise preserve the
	// transport's initialize negotiation, including its legacy fallback. A
	// legacy per-request version can't downgrade a modern negotiation, which
	// would otherwise drop the request's routing and parameter headers.
	if version := ParseMCPFrame(msg).ProtocolVersion; version >= currentMCPVersion {
		return version
	}
	return b.client.ProtocolVersion()
}

func (b *mcpBridgeHeaders) prepare(ctx context.Context, msg []byte) (http.Header, error) {
	version := b.version(msg)
	if version < currentMCPVersion {
		return nil, nil
	}
	frame := ParseMCPFrame(msg)
	if frame.Method == methodToolsCall && !isRPCNotification(frame.ID) {
		if frame.RoutingNameErr != nil || frame.RoutingName == "" {
			return nil, fmt.Errorf("invalid tool routing name")
		}
		req := &http.Request{Header: make(http.Header)}
		req = req.WithContext(ctx)
		req.Header.Set(listenerProtocolVersion, version)
		release, err := b.state.acquireToolContract(ctx, frame.RoutingName, func() error {
			return discoverMCPToolContract(mcpContractDiscoveryRequest{
				request: req, state: b.state, bridge: b.client, opts: b.opts, log: b.log, tool: frame.RoutingName,
			})
		})
		if err != nil {
			return nil, fmt.Errorf("cannot establish tool header contract: %w", err)
		}
		defer release()
	}
	headers, err := synthesizeMCPRequestHeaders(frame, b.state.baseline)
	if err != nil {
		return nil, err
	}
	headers.Set(listenerProtocolVersion, version)
	return headers, nil
}
