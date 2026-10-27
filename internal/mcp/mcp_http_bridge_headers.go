// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"

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

	mu sync.Mutex
	// negotiated keeps the first modern version the transport reports. The
	// transport clears its copy on a new handshake and when the session ends,
	// and an empty version would read as legacy and send no request metadata.
	// Once modern, this bridge stays modern for its lifetime.
	negotiated string
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
	return b.negotiatedVersion()
}

func (b *mcpBridgeHeaders) negotiatedVersion() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	version := b.client.ProtocolVersion()
	if version >= currentMCPVersion {
		b.negotiated = version
	}
	if b.negotiated != "" {
		return b.negotiated
	}
	return version
}

func (b *mcpBridgeHeaders) prepare(ctx context.Context, msg []byte) (http.Header, error) {
	version := b.version(msg)
	if version < currentMCPVersion {
		return nil, nil
	}
	if !validMCPProtocolVersion([]string{version}) {
		// Lexical comparison admits malformed dates such as 2026-99-99; the
		// listener accepts only canonical YYYY-MM-DD, so refuse them here
		// rather than forward an unusable protocol header.
		return nil, fmt.Errorf("invalid MCP protocol version")
	}
	frame := ParseMCPFrame(msg)
	if frame.Method == "initialize" && b.negotiatedVersion() >= currentMCPVersion {
		// This process already established its modern header contract. A
		// second handshake would clear the transport's negotiated version,
		// including while deferred calls can be released. Refuse it before
		// that reset rather than let those calls take the legacy path.
		return nil, fmt.Errorf("modern bridge is already initialized")
	}
	if isRPCNotification(frame.ID) {
		switch frame.Method {
		case methodToolsCall, methodResourcesRead, methodPromptsGet:
			// MCP defines these methods only as requests, which must carry
			// Mcp-Name and parameter mirrors. A notification form would leave
			// unmirrored, so it is refused like an unavailable contract.
			return nil, fmt.Errorf("%s cannot be sent as a notification", frame.Method)
		}
	}
	if frame.Method == methodToolsCall {
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
