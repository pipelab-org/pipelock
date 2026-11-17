// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"sync"
)

// DLPWarnContext carries per-request metadata for scanner observations.
// DLP and prompt-injection warnings share transport attribution, never content.
type DLPWarnContext struct {
	Method     string
	URL        string
	Target     string
	Resource   string
	ClientIP   string
	RequestID  string
	Agent      string
	ServerName string
	Transport  string // "fetch", "forward", "connect", "intercept", "reverse", "websocket", "mcp_stdio", "mcp_http"
	PolicyHash string
	// PromptInjectionMode belongs to the same scanner snapshot as PolicyHash.
	PromptInjectionMode string
}

type dlpWarnCtxKey struct{}

// WithDLPWarnContext attaches DLP warn metadata to a context.
func WithDLPWarnContext(ctx context.Context, wc DLPWarnContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, dlpWarnCtxKey{}, wc)
}

// DLPWarnContextFromCtx extracts DLP warn metadata from a context.
// Returns zero value if not set.
func DLPWarnContextFromCtx(ctx context.Context) DLPWarnContext {
	if ctx == nil {
		return DLPWarnContext{}
	}
	wc, _ := ctx.Value(dlpWarnCtxKey{}).(DLPWarnContext)
	return wc
}

type dlpWarnBufferKey struct{}

type bufferedDLPWarning struct {
	ctx      context.Context
	hook     func(context.Context, string, string)
	name     string
	severity string
}

type dlpWarnBuffer struct {
	mu       sync.Mutex
	warnings []bufferedDLPWarning
}

// BufferDLPWarnings defers warning hooks until replay is called. A caller
// scanning independent views concurrently gives each view its own buffer,
// joins those scans, then replays on the request goroutine in view order.
func BufferDLPWarnings(ctx context.Context) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	buffer := &dlpWarnBuffer{}
	return context.WithValue(ctx, dlpWarnBufferKey{}, buffer), func() {
		buffer.mu.Lock()
		warnings := buffer.warnings
		buffer.warnings = nil
		buffer.mu.Unlock()
		for _, warning := range warnings {
			warning.hook(warning.ctx, warning.name, warning.severity)
		}
	}
}

func bufferDLPWarning(ctx context.Context, hook func(context.Context, string, string), match WarnMatch) bool {
	buffer, _ := ctx.Value(dlpWarnBufferKey{}).(*dlpWarnBuffer)
	if buffer == nil {
		return false
	}
	// Nested scans from a callback retain the ordinary immediate behavior.
	callbackCtx := context.WithValue(ctx, dlpWarnBufferKey{}, (*dlpWarnBuffer)(nil))
	buffer.mu.Lock()
	buffer.warnings = append(buffer.warnings, bufferedDLPWarning{ctx: callbackCtx, hook: hook, name: match.PatternName, severity: match.Severity})
	buffer.mu.Unlock()
	return true
}
