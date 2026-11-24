// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !mcp_hardening_test

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type mcpSandboxBridgeStartOptions struct {
	Rec              session.Recorder
	Context          context.Context
	Cancel           context.CancelFunc
	Config           *config.Config
	KillSwitch       *killswitch.Controller
	AuditLogger      *audit.Logger
	Metrics          *metrics.Metrics
	MetricsBoundAddr string
	ReceiptWriter    *v3.StreamWriter
	ReceiptEmitter   *receipt.Emitter
	V2ReceiptEmitter *proxydecision.Emitter
	ReceiptGroup     *mcp.MCPReceiptGroup
	EnvelopeEmitter  *envelope.Emitter
}

type startMCPSandboxBridgeFunc func(mcpSandboxBridgeStartOptions) (*mcpSandboxBridge, error)

type mcpSandboxBridgeSetupOptions struct {
	Rec              session.Recorder
	Context          context.Context
	Cancel           context.CancelFunc
	GOOS             string
	Config           *config.Config
	KillSwitch       *killswitch.Controller
	AuditLogger      *audit.Logger
	Metrics          *metrics.Metrics
	MetricsBoundAddr string
	ReceiptWriter    *v3.StreamWriter
	ReceiptEmitter   *receipt.Emitter
	V2ReceiptEmitter *proxydecision.Emitter
	ReceiptGroup     *mcp.MCPReceiptGroup
	EnvelopeEmitter  *envelope.Emitter
	Stderr           io.Writer
	LaunchConfig     *sandbox.LaunchConfig
	StartBridge      startMCPSandboxBridgeFunc
}

type mcpSandboxBridge struct {
	dir        string
	socketPath string
	listener   net.Listener
	scanner    *scanner.Scanner
	proxy      *proxy.Proxy
	server     httpstream.GatedServer
	serveDone  chan struct{}
	closeOnce  sync.Once
	closeErr   error
}

func setupMCPSandboxBridge(opts mcpSandboxBridgeSetupOptions) (func() error, error) {
	if opts.GOOS != "linux" {
		_, _ = fmt.Fprintf(opts.Stderr,
			"pipelock: WARNING: MCP sandbox egress bridge is Linux-only; bridge-style MCP servers on %s may need separate egress controls to ensure upstream HTTP(S) traverses pipelock. "+
				"Configure the MCP server to use pipelock's forward proxy listener via HTTPS_PROXY and disable any built-in proxy bypass.\n",
			opts.GOOS)
		return func() error { return nil }, nil
	}

	bridge, err := opts.StartBridge(mcpSandboxBridgeStartOptions{
		Rec:              opts.Rec,
		Context:          opts.Context,
		Cancel:           opts.Cancel,
		Config:           opts.Config,
		KillSwitch:       opts.KillSwitch,
		AuditLogger:      opts.AuditLogger,
		Metrics:          opts.Metrics,
		MetricsBoundAddr: opts.MetricsBoundAddr,
		ReceiptWriter:    opts.ReceiptWriter,
		ReceiptEmitter:   opts.ReceiptEmitter,
		V2ReceiptEmitter: opts.V2ReceiptEmitter,
		ReceiptGroup:     opts.ReceiptGroup,
		EnvelopeEmitter:  opts.EnvelopeEmitter,
	})
	if err != nil {
		return nil, err
	}
	opts.LaunchConfig.BridgeSocketPath = bridge.SocketPath()
	_, _ = fmt.Fprintf(opts.Stderr,
		"pipelock: MCP sandbox egress bridge enabled; forward_proxy forced on for sandboxed MCP egress (child loopback -> parent scanner)\n")
	return bridge.Close, nil
}

func isNilBridgeRecorder(rec session.Recorder) bool {
	if rec == nil {
		return true
	}
	v := reflect.ValueOf(rec)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return v.IsNil()
	default:
		return false
	}
}

func startMCPSandboxBridge(opts mcpSandboxBridgeStartOptions) (*mcpSandboxBridge, error) {
	if opts.Config.Taint.Enabled {
		_, riskOK := opts.Rec.(session.RiskState)
		_, taskOK := opts.Rec.(session.TaskPermissionState)
		if !riskOK || !taskOK || isNilBridgeRecorder(opts.Rec) {
			return nil, fmt.Errorf("MCP sandbox bridge: taint requires a shared session risk recorder")
		}
	}
	onRequiredFailure, err := bridgeRequiredReceiptFailure(opts.ReceiptGroup, opts.Config.FlightRecorder.RequireReceipts, opts.Cancel)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "pl-mcp-*")
	if err != nil {
		return nil, fmt.Errorf("creating MCP sandbox bridge dir: %w", err)
	}

	bridge := &mcpSandboxBridge{dir: dir}
	bridge.socketPath = sandbox.ProxySocketPath(dir)

	ln, err := (&net.ListenConfig{}).Listen(opts.Context, "unix", bridge.socketPath)
	if err != nil {
		_ = bridge.Close()
		return nil, fmt.Errorf("MCP sandbox bridge listen: %w", err)
	}
	bridge.listener = ln

	if err := os.Chmod(bridge.socketPath, 0o600); err != nil {
		_ = bridge.Close()
		return nil, fmt.Errorf("MCP sandbox bridge socket permissions: %w", err)
	}

	egressCfg := opts.Config.Clone()
	egressCfg.ForwardProxy.Enabled = true
	bridge.scanner, err = scanner.New(egressCfg)
	if err != nil {
		_ = bridge.Close()
		return nil, fmt.Errorf("create MCP sandbox bridge scanner: %w", err)
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.New()
	}
	bridge.scanner.SetDLPWarnHook(func(ctx context.Context, patternName, severity string) {
		emitDLPWarn(opts.AuditLogger, opts.Metrics, opts.ReceiptEmitter, ctx, patternName, severity)
	})
	wirePromptInjectionAudit(bridge.scanner, opts.AuditLogger)

	proxyOptions := []proxy.Option{
		proxy.WithTaintRecorder(opts.Rec),
		proxy.WithKillSwitch(opts.KillSwitch),
		proxy.WithV3ReceiptWriter(opts.ReceiptWriter),
		proxy.WithReceiptEmitter(opts.ReceiptEmitter),
		proxy.WithV2ReceiptEmitter(opts.V2ReceiptEmitter),
		proxy.WithEnvelopeEmitter(opts.EnvelopeEmitter),
	}
	if opts.ReceiptGroup != nil {
		groupOption, groupErr := proxy.WithReceiptShardSet(opts.ReceiptGroup.Shards, opts.ReceiptGroup.V2, onRequiredFailure)
		if groupErr != nil {
			_ = bridge.Close()
			return nil, fmt.Errorf("MCP sandbox bridge receipt group: %w", groupErr)
		}
		proxyOptions = append(proxyOptions, groupOption)
	}
	p, err := proxy.New(egressCfg, opts.AuditLogger, bridge.scanner, opts.Metrics, proxyOptions...)
	if err != nil {
		_ = bridge.Close()
		return nil, fmt.Errorf("MCP sandbox bridge proxy init: %w", err)
	}
	bridge.proxy = p
	if err := p.LoadCertCache(egressCfg); err != nil {
		_ = bridge.Close()
		return nil, fmt.Errorf("MCP sandbox bridge TLS interception: %w", err)
	}
	if opts.MetricsBoundAddr != "" {
		p.UpdateMetricsDialTargetFromBoundAddr(opts.MetricsBoundAddr)
	}
	bridge.serve(p.Handler())
	go func() {
		select {
		case <-opts.Context.Done():
			_ = bridge.Close()
		case <-bridge.serveDone:
		}
	}()

	return bridge, nil
}

func bridgeRequiredReceiptFailure(group *mcp.MCPReceiptGroup, required bool, cancel context.CancelFunc) (func(error), error) {
	if group == nil || !required {
		return nil, nil
	}
	if cancel == nil {
		return nil, fmt.Errorf("MCP sandbox bridge required receipt group has no cancellation callback")
	}
	return func(error) { cancel() }, nil
}

func (b *mcpSandboxBridge) SocketPath() string {
	if b == nil {
		return ""
	}
	return b.socketPath
}

func (b *mcpSandboxBridge) serve(handler http.Handler) {
	gate := &httpstream.Gate{}
	b.server = httpstream.GatedServer{
		Gate: gate,
		Server: &http.Server{
			Handler:           gate.Wrap(handler),
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       30 * time.Second,
		},
	}
	b.serveDone = make(chan struct{})
	go func() {
		defer close(b.serveDone)
		_ = b.server.Server.Serve(b.listener)
	}()
}

func (b *mcpSandboxBridge) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		if b.serveDone != nil {
			ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer cancel()
			if err := httpstream.DrainServer(ctx, b.server); err != nil {
				b.closeErr = errors.Join(httpstream.ErrShutdownIncomplete, err)
			}
			<-b.serveDone
		} else if b.listener != nil {
			_ = b.listener.Close()
		}
		if b.proxy != nil {
			b.proxy.Close()
		} else if b.scanner != nil {
			b.scanner.Close()
		}
		if b.dir != "" {
			_ = os.RemoveAll(b.dir)
		}
	})
	return b.closeErr
}
