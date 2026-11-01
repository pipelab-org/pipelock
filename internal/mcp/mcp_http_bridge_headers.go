// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

var (
	errBridgeRoutedNotification = errors.New("routed MCP method requires a non-null request ID")
	errBridgeAlreadyInitialized = errors.New("modern bridge is already initialized")
)

func bridgeHeaderRefusal(err error) (mcpDenialAudit, string, string) {
	switch {
	case errors.Is(err, errBridgeRoutedNotification):
		return mcpBridgeNotificationDenialAudit(), "pipelock: " + errBridgeRoutedNotification.Error(), "bridge_routed_notification"
	case errors.Is(err, errBridgeAlreadyInitialized):
		return mcpBridgeInitializeDenialAudit(), "pipelock: " + errBridgeAlreadyInitialized.Error(), "bridge_already_initialized"
	default:
		return mcpListenerInspectionDenialAudit(), "pipelock: cannot establish tool header contract", "tool_header_contract_unavailable"
	}
}

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
	frame := ParseMCPFrame(msg)
	// Versions are compared lexically, so a malformed per-request value can
	// sort on either side of the current revision (2026-99-99 above it,
	// 2026-07-2 below it). The listener accepts only canonical YYYY-MM-DD, so
	// refuse any malformed value before it selects the modern or legacy path.
	if frame.ProtocolVersionPresent && !validMCPProtocolVersion([]string{frame.ProtocolVersion}) {
		return nil, fmt.Errorf("invalid MCP protocol version")
	}
	version := b.version(msg)
	if version < currentMCPVersion {
		return nil, nil
	}
	if !validMCPProtocolVersion([]string{version}) {
		return nil, fmt.Errorf("invalid MCP protocol version")
	}
	if frame.Method == "initialize" && b.negotiatedVersion() >= currentMCPVersion {
		// This process already established its modern header contract. A
		// second handshake would clear the transport's negotiated version,
		// including while deferred calls can be released. Refuse it before
		// that reset rather than let those calls take the legacy path.
		return nil, errBridgeAlreadyInitialized
	}
	if isRPCNotification(frame.ID) && routingFieldForMethod(frame.Method) != "" {
		// MCP defines these methods only as requests, which must carry
		// Mcp-Name and parameter mirrors. A notification form would leave
		// unmirrored, so it is refused like an unavailable contract.
		return nil, errBridgeRoutedNotification
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

// prepareForRelease uses the held-call kill-switch epoch and polling cadence
// while waiting for discovery or the inventory lock. The send claim remains
// the final authority; cancellation only shortens an already refused release.
func (b *mcpBridgeHeaders) prepareForRelease(ctx context.Context, msg []byte, generation uint64) (http.Header, error) {
	ks := b.opts.KillSwitch
	if ks == nil {
		return b.prepare(ctx, msg)
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(deferKillSwitchPollInterval)
		defer ticker.Stop()
		for {
			if ks.DeferredGeneration() != generation || ks.IsActive() {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() {
		cancel()
		<-done
	}()
	return b.prepare(ctx, msg)
}
