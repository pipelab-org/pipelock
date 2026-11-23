// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	guardfs "github.com/luckyPipewrench/pipelock/internal/guard"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const testTLSCALoadError = "load TLS CA: no PEM block in CA cert file"

func TestSandboxTLSInterception(t *testing.T) {
	for _, caState := range []string{"valid", "missing", "invalid", "disabled"} {
		t.Run(caState, func(t *testing.T) {
			caPath, keyPath, roots := standaloneTestCA(t, caState)
			path := writeServerTestConfig(t, fmt.Sprintf(`ssrf:
  ip_allowlist: ['127.0.0.0/8']
forward_proxy:
  sni_verification: false
  sni_require_tls: false
tls_interception:
  enabled: %t
  ca_cert: %q
  ca_key: %q
`, caState != "disabled", caPath, keyPath))
			launched := false
			cmd := sandboxCmd(func(launch sandbox.StandaloneLaunchConfig) error {
				launched = true
				if roots != nil {
					assertStandaloneInterceptedConnect(t, launch.ProxyHandler, roots)
				}
				return nil
			})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"--config", path, "--workspace", t.TempDir(), "--", "/usr/bin/true"})
			err := cmd.ExecuteContext(t.Context())
			wantErr := ""
			switch caState {
			case "missing":
				wantErr = "CA cert not found at " + caPath
			case "invalid":
				wantErr = testTLSCALoadError
			}
			assertStandaloneTLSStartup(t, err, launched, wantErr)
		})
	}
}

func TestGuardTLSInterception(t *testing.T) {
	for _, caState := range []string{"valid", "missing", "invalid", "disabled"} {
		t.Run(caState, func(t *testing.T) {
			caPath, keyPath, roots := standaloneTestCA(t, caState)
			cfg := config.Defaults()
			cfg.TLSInterception.Enabled = caState != "disabled"
			cfg.TLSInterception.CACertPath = caPath
			cfg.TLSInterception.CAKeyPath = keyPath
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
			cfg.ForwardProxy.SNIVerification = new(false)
			cfg.ForwardProxy.SNIRequireTLS = new(false)
			launched := false
			err := launchGuard(GuardLaunchOptions{
				Context:   t.Context(),
				Config:    cfg,
				Workspace: t.TempDir(),
				Command:   []string{"/usr/bin/true"},
				Stderr:    io.Discard,
			}, func(launch sandbox.StandaloneLaunchConfig) error {
				launched = true
				if roots == nil {
					return nil
				}
				proof := guardfs.NewExecutionProof(
					guardfs.EnforcementRecord{State: guardfs.EnforcementEnforced, Mechanism: "landlock", Coverage: guardfs.CoverageFull},
					guardfs.ExecControlOptions{
						PolicyHash: launch.GuardPolicyHash, Workspace: launch.Workspace,
						TempDir: launch.Workspace, Binary: launch.Command[0],
					}, launch.Command,
				)
				encoded, err := json.Marshal(proof)
				if err != nil {
					return err
				}
				if err := launch.GuardAppliedPreExec(launch.Workspace, encoded); err != nil {
					return err
				}
				assertStandaloneInterceptedConnect(t, launch.ProxyHandler, roots)
				return nil
			})
			wantErr := ""
			switch caState {
			case "missing":
				wantErr = "load TLS CA: read CA cert: open " + caPath
			case "invalid":
				wantErr = testTLSCALoadError
			}
			assertStandaloneTLSStartup(t, err, launched, wantErr)
		})
	}
}

func standaloneTestCA(t *testing.T, state string) (certPath, keyPath string, roots *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	switch state {
	case "valid":
		ca, key, _, err := certgen.GenerateCA("Test CA", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := certgen.SaveCA(certPath, keyPath, ca, key); err != nil {
			t.Fatal(err)
		}
		roots = x509.NewCertPool()
		roots.AddCert(ca)
	case "invalid":
		// Exist on disk so file checks pass and the startup loader reads the CA.
		for _, path := range []string{certPath, keyPath} {
			if err := os.WriteFile(path, []byte("invalid PEM"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return certPath, keyPath, roots
}

func assertStandaloneTLSStartup(t *testing.T, err error, launched bool, wantErr string) {
	t.Helper()
	if wantErr == "" {
		if err != nil || !launched {
			t.Fatalf("startup error = %v, launched = %t", err, launched)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), wantErr) || launched {
		t.Fatalf("startup error = %v, launched = %t, want %q before launch", err, launched, wantErr)
	}
}

func assertStandaloneInterceptedConnect(t *testing.T, handler func(net.Conn), roots *x509.CertPool) {
	t.Helper()
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	go handler(server)
	if err := client.SetDeadline(time.Now().Add(testwait.Deadline(5 * time.Second))); err != nil {
		t.Fatal(err)
	}
	const host = "127.0.0.1"
	target := net.JoinHostPort(host, "443")
	if _, err := fmt.Fprintf(client, "%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", http.MethodConnect, target, target); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	// CONNECT's 200 arrives before TLS. Verify the leaf against the configured CA.
	tlsConn := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("intercepted CONNECT TLS handshake: %v", err)
	}
}
