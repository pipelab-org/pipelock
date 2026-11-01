// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// sandboxUnavailableMarker is printed by a re-executed test child whose runner
// cannot launch a sandbox. A skipped child exits zero, so the parent reads
// this line to report a skip instead of a pass.
const sandboxUnavailableMarker = "PIPELOCK-TEST-SANDBOX-UNAVAILABLE: "

// skipChildWithoutSandboxLaunch runs inside the re-executed child. It launches
// a trivial sandboxed command, as the sandbox package's own launch tests do,
// and skips when the runner cannot create one (for example, when the network
// namespace cannot configure loopback).
func skipChildWithoutSandboxLaunch(t *testing.T) {
	t.Helper()
	reason := ""
	if caps := sandbox.Detect(); !caps.UserNamespaces {
		reason = "user namespaces unavailable"
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(10*time.Second))
		defer cancel()
		var stderr bytes.Buffer
		cmd, err := sandbox.LaunchSandboxed(sandbox.LaunchConfig{Ctx: ctx, Command: []string{"true"}, Workspace: t.TempDir(), Stderr: &stderr})
		if err == nil {
			err = cmd.Wait()
		}
		switch {
		case err != nil:
			reason = fmt.Sprintf("%v: %s", err, strings.TrimSpace(stderr.String()))
		case strings.Contains(stderr.String(), "[sandbox] loopback:"):
			// The child reports a loopback failure and keeps running; these
			// tests reach the proxy over loopback, so they cannot pass.
			reason = strings.TrimSpace(stderr.String())
		}
	}
	if reason != "" {
		fmt.Println(sandboxUnavailableMarker + strings.ReplaceAll(reason, "\n", " "))
		t.Skip("sandbox launch unavailable: " + reason)
	}
}

// skipParentIfChildLacksSandbox converts the child's marker into a skip.
func skipParentIfChildLacksSandbox(t *testing.T, output []byte) {
	t.Helper()
	if _, reason, ok := strings.Cut(string(output), sandboxUnavailableMarker); ok {
		line, _, _ := strings.Cut(reason, "\n")
		t.Skip("sandbox launch unavailable in this runner: " + line)
	}
}
