// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
// a trivial sandboxed command with a bridge socket, which makes sandbox-init
// bring up loopback in the new network namespace, as both the standalone
// sandbox and the MCP bridge do. It skips only for known runner limits: no
// user namespaces, or a namespace that cannot configure loopback. Any other
// launch failure is a regression and fails the test.
func skipChildWithoutSandboxLaunch(t *testing.T) {
	t.Helper()
	reason := ""
	if caps := sandbox.Detect(); !caps.UserNamespaces {
		reason = "user namespaces unavailable"
	} else {
		// Unix socket paths are short; t.TempDir can exceed the limit.
		sockDir, err := os.MkdirTemp("", "plprobe")
		if err != nil {
			t.Fatalf("probe socket dir: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
		sockPath := filepath.Join(sockDir, "bridge.sock")
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sockPath)
		if err != nil {
			t.Fatalf("probe bridge listener: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(10*time.Second))
		defer cancel()
		var stderr bytes.Buffer
		cmd, err := sandbox.LaunchSandboxed(sandbox.LaunchConfig{
			Ctx:              ctx,
			Command:          []string{"true"},
			Workspace:        t.TempDir(),
			BridgeSocketPath: sockPath,
			Stderr:           &stderr,
		})
		if err == nil {
			err = cmd.Wait()
		}
		const loopbackFailure = "[sandbox] loopback:"
		switch {
		case err != nil && strings.Contains(stderr.String(), loopbackFailure):
			// sandbox-init exits when loopback cannot be configured; these
			// tests reach the proxy over loopback, so they cannot pass here.
			_, line, _ := strings.Cut(stderr.String(), loopbackFailure)
			line, _, _ = strings.Cut(line, "\n")
			reason = "loopback: " + strings.TrimSpace(line)
		case err != nil:
			t.Fatalf("sandbox probe launch failed: %v: %s", err, strings.TrimSpace(stderr.String()))
		}
	}
	if reason != "" {
		fmt.Printf("%s%s\n", sandboxUnavailableMarker, reason)
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
