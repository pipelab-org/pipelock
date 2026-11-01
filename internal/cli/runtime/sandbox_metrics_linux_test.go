// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
	"golang.org/x/net/dns/dnsmessage"
)

func TestSandboxMetricsBindFailurePrecedesLaunch(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", serverTestEphemeralListen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	workspace := t.TempDir()
	marker := filepath.Join(workspace, "launched")
	path := writeServerTestConfig(t, fmt.Sprintf("metrics_listen: %q\n", ln.Addr().String()))
	cmd := SandboxCmd()
	cmd.SetArgs([]string{"--config", path, "--workspace", workspace, "--", "/bin/sh", "-c", "touch launched"})
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "metrics_listen bind") {
		t.Fatalf("sandbox error = %v, want metrics bind refusal; output=%s", err, output.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("workload ran before metrics bind refusal: %v", err)
	}
	if strings.Contains(output.String(), "launching sandboxed process") {
		t.Fatal("launch announced before bind refusal")
	}
}

func TestSandboxMetricsListenerAndAgentRoutes(t *testing.T) {
	// Check prerequisites before re-executing: a skip inside the child exits
	// zero, which the parent would otherwise report as a pass.
	if sandbox.Detect().LandlockABI == 0 {
		t.Skip("kernel does not support Landlock")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is required for real sandbox traffic")
	}
	// MCP command tests harden their process with PR_SET_DUMPABLE=0. Execute
	// this standalone launch in a fresh process, as a separate CLI invocation
	// would run, so earlier MCP tests cannot affect user-namespace re-execution.
	const helperEnv = "PIPELOCK_TEST_SANDBOX_METRICS"
	if os.Getenv(helperEnv) != "1" {
		ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(time.Minute))
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSandboxMetricsListenerAndAgentRoutes$", "-test.timeout=50s") // #nosec G204 G702 -- test re-execs its own binary with fixed arguments
		child.Env = append(os.Environ(), helperEnv+"=1")
		output, err := child.CombinedOutput()
		skipParentIfChildLacksSandbox(t, output)
		if err != nil {
			t.Fatalf("standalone invocation: %v\n%s", err, output)
		}
		return
	}
	skipChildWithoutSandboxLaunch(t)
	for _, mode := range []string{"off", "numeric", "hostname-drift"} {
		t.Run(mode, func(t *testing.T) {
			configured := mode != "off"
			workspace := t.TempDir()
			metricsAddr := ""
			body := "ssrf:\n  ip_allowlist: ['127.0.0.0/8']\n"
			if configured {
				metricsAddr = testport.ListenAddrs(t, 1)[0]
				configuredAddr := metricsAddr
				if mode == "hostname-drift" {
					_, port, splitErr := net.SplitHostPort(metricsAddr)
					if splitErr != nil {
						t.Fatal(splitErr)
					}
					metricsAddr = net.JoinHostPort("127.0.0.2", port)
					configuredAddr = net.JoinHostPort("metrics.vendor.example", port)
					var lookups atomic.Int32
					useMetricsTestDNS(t, func() [4]byte {
						if lookups.Add(1) == 1 {
							return [4]byte{127, 0, 0, 1}
						}
						return [4]byte{127, 0, 0, 2}
					})
				}
				body += fmt.Sprintf("metrics_listen: %q\n", configuredAddr)
			}
			// The workload reaches this origin through its actual proxy bridge. The
			// parent observes the dedicated listener while the workload is still live.
			observed := make(chan error, 1)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
				defer client.CloseIdleConnections()
				for _, route := range []string{"/metrics", "/stats"} {
					if metricsAddr == "" {
						break
					}
					req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://"+metricsAddr+route, nil)
					if err != nil {
						observed <- err
						return
					}
					resp, err := client.Do(req)
					if err != nil {
						observed <- err
						return
					}
					data, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if readErr != nil {
						observed <- fmt.Errorf("read dedicated %s: %w", route, readErr)
						return
					}
					if resp.StatusCode != http.StatusOK || len(data) == 0 {
						observed <- fmt.Errorf("dedicated %s returned %d, bytes=%d", route, resp.StatusCode, len(data))
						return
					}
				}
				observed <- nil
				_, _ = io.WriteString(w, "sandbox-origin-ok")
			}))
			defer origin.Close()
			path := writeServerTestConfig(t, body)
			script := `set -eu
for route in health metrics stats; do
 curl --max-time 5 --noproxy '*' -s -o /dev/null -w '%{http_code}\n' "$HTTP_PROXY/$route" >> routes
 done
curl --max-time 5 --noproxy '*' --fail -s "$HTTP_PROXY/fetch?url=$1" > origin-result
`
			cmd := SandboxCmd()
			if configured {
				script += `curl --max-time 5 --noproxy '*' -s -o /dev/null -w '%{http_code}\n' "$HTTP_PROXY/fetch?url=http://$2/stats" > metrics-dial
`
			}
			cmd.SetArgs([]string{"--config", path, "--workspace", workspace, "--best-effort", "--best-effort-reason", "test host isolation", "--best-effort-expiry", "1m", "--", "/bin/sh", "-c", script, "metrics-test", origin.URL, metricsAddr})
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("sandbox: %v; output=%s", err, output.String())
			}
			routes, err := os.ReadFile(filepath.Clean(filepath.Join(workspace, "routes")))
			if err != nil || string(routes) != "200\n404\n404\n" {
				t.Fatalf("agent routes = %q, %v; output=%s", routes, err, output.String())
			}
			select {
			case err := <-observed:
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("workload never reached the controlled origin")
			}
			result, err := os.ReadFile(filepath.Clean(filepath.Join(workspace, "origin-result")))
			if err != nil || !bytes.Contains(result, []byte("sandbox-origin-ok")) {
				t.Fatalf("origin result = %q, %v", result, err)
			}
			if !configured {
				if strings.Contains(output.String(), "metrics listening on") || !strings.Contains(output.String(), "metrics not exposed; set metrics_listen") {
					t.Fatal("unexpected metrics notice: " + output.String())
				}
			} else {
				dialStatus, readErr := os.ReadFile(filepath.Clean(filepath.Join(workspace, "metrics-dial")))
				if readErr != nil || string(dialStatus) != "403\n" {
					t.Fatalf("agent metrics dial = %q, %v; output=%s", dialStatus, readErr, output.String())
				}
				rebound, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", metricsAddr)
				if err != nil {
					t.Fatalf("metrics listener leaked after workload exit: %v", err)
				}
				_ = rebound.Close()
			}
		})
	}
}

// useMetricsTestDNS models a hostname resolving differently at config load and
// listener bind. DNS responses use the standard wire codec, and the listener
// still binds a real local TCP socket.
func useMetricsTestDNS(t *testing.T, address func() [4]byte) {
	t.Helper()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			var length [2]byte
			if _, err := io.ReadFull(server, length[:]); err != nil {
				return
			}
			packet := make([]byte, int(length[0])<<8|int(length[1]))
			if _, err := io.ReadFull(server, packet); err != nil {
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(packet); err != nil {
				return
			}
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: true, RecursionAvailable: true}, Questions: query.Questions}
			for _, question := range query.Questions {
				if question.Type == dnsmessage.TypeA {
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: address()}})
				}
			}
			wire, err := reply.Pack()
			if err != nil {
				return
			}
			length[0], length[1] = byte((len(wire)>>8)&0xff), byte(len(wire)&0xff)
			_, _ = server.Write(append(length[:], wire...))
		}()
		return client, nil
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
}
