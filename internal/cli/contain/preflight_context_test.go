// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestDoctorCommandStableContext(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux diagnostic process context")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	// A preload exercises Node's package lookup before the -e program runs,
	// just as NODE_OPTIONS=--require does for the installed proxy shim.
	shim := filepath.Join(t.TempDir(), "shim.cjs")
	if err := os.WriteFile(shim, []byte("require('node:http');"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"invalid package", "unreadable package", "unreadable cwd", "removed cwd"} {
		t.Run(name, func(t *testing.T) {
			cwd := t.TempDir()
			pkg := filepath.Join(cwd, "package.json")
			if err := os.WriteFile(pkg, []byte("invalid json"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Chdir(cwd)
			switch name {
			case "unreadable package":
				if err := os.Chmod(pkg, 0); err != nil {
					t.Fatal(err)
				}
			case "unreadable cwd":
				if err := os.Chmod(cwd, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(cwd, 0o750) }) //nolint:gosec // G302: restore directory traversal for TempDir cleanup.
			case "removed cwd":
				if err := os.Remove(pkg); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(cwd); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			env := defaultDoctorEnv()
			out, code, err := env.runCmd(ctx, node, "--require", shim, "-e", "process.stdout.write('200')")
			if err != nil || code != 0 || out != "200" {
				t.Fatalf("doctor node: output=%q code=%d error=%v", out, code, err)
			}
		})
	}
}

func TestInstallNFTPreflightBeforeMutation(t *testing.T) {
	policy := reconcileTestPolicy()
	healthy := wrapNFTListingForTest(nftListingFromRulesBodyForTest(policy.rules, 20))
	for _, dryRun := range []bool{true, false} {
		for _, tc := range []struct {
			name, live, want string
			code             int
			missingUser      bool
		}{
			{"agent accept", strings.Replace(healthy, "type filter", "meta skuid 987 accept # handle 10\n type filter", 1), "nft reconciliation conflict:", 0, false},
			{"unknown observation", "unrecognized nft failure", "list nft managed chain", 1, false},
			{"permission denied", "Operation not permitted", "list nft managed chain", 1, false},
			{"empty observation", "", "chain", 0, false},
			{"missing identity on installed host", healthy, "lookup pipelock-agent", 0, true},
		} {
			t.Run(tc.name+"/dry="+strconv.FormatBool(dryRun), func(t *testing.T) {
				env, runner, _ := newFakeEnv(t)
				binDir := installContainCommandFixtures(t)
				env.nftPath = filepath.Join(binDir, "nft")
				stat := env.stat
				env.stat = func(path string) (os.FileInfo, error) {
					if path == env.nftPath {
						return fakeFileInfo{mode: 0o700, sys: fakeFileSysWithUID(0)}, nil
					}
					if path == "/usr/local/bin/claude" {
						return stat(env.pipelockBinary)
					}
					return stat(path)
				}
				src := filepath.Join(t.TempDir(), "pipelock.yaml")
				if err := os.WriteFile(src, []byte("mode: balanced\nforward_proxy:\n  enabled: true\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				runner.on(argvFor(env.nftPath, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), tc.live, tc.code, nil)
				lookup := env.lookupUser
				if tc.missingUser {
					env.lookupUser = func(name string) (*user.User, error) {
						if name == env.agentUserName {
							return nil, user.UnknownUserError(name)
						}
						return lookup(name)
					}
				}
				mutations := 0
				env.mkdirAll = func(string, os.FileMode) error { mutations++; return errors.New("unexpected mkdir") }
				env.writeFile = func(string, []byte, os.FileMode) error { mutations++; return errors.New("unexpected write") }
				env.chmod = func(string, os.FileMode) error { mutations++; return errors.New("unexpected chmod") }
				env.chown = func(string, int, int) error { mutations++; return errors.New("unexpected chown") }
				err := runInstall(t.Context(), env, installOpts{dryRun: dryRun, configSource: src})
				if err == nil || !strings.Contains(err.Error(), tc.want) || cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
					t.Fatalf("install error=%v, want preflight refusal containing %q", err, tc.want)
				}
				if mutations != 0 {
					t.Fatalf("failed preflight mutated %d times", mutations)
				}
				if len(runner.calls) != 1 || runner.calls[0].name != env.nftPath || strings.Join(runner.calls[0].args, " ") != "-n -a list chain inet "+defaultNFTTable+" "+defaultNFTChain {
					t.Fatalf("failed preflight ran commands beyond nft observation: %+v", runner.calls)
				}
				assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
			})
		}
	}
}

func TestDoctorCommandFailureClassification(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux diagnostic process context")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for _, tc := range []struct {
		name, dir, binary string
		args              []string
		launchError       bool
	}{
		{"missing binary", "/", "/nonexistent/contain-doctor", nil, true},
		{"missing working directory", filepath.Join(t.TempDir(), "missing"), "/bin/sh", []string{"-c", "exit 0"}, true},
		{"sudo refusal", "/", "/bin/sh", []string{"-c", "echo 'sudo: a password is required' >&2; exit 1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code, err := runCommandInDir(ctx, tc.dir, tc.binary, tc.args...)
			if (err != nil) != tc.launchError || (tc.launchError && code != -1) || (!tc.launchError && code != 1) {
				t.Fatalf("output=%q code=%d error=%v", out, code, err)
			}
			result, done := classifyAgentRun(out, err, "node", defaultProxyPort)
			if !done || result.status != statusSkip || result.class != classNone {
				t.Fatalf("launch/refusal became a proxy verdict: %+v", result)
			}
		})
	}
	// Existing callers still inherit cwd; doctor does not change their contract.
	cwd := t.TempDir()
	t.Chdir(cwd)
	out, code, err := realRunCommand(ctx, "/bin/pwd")
	if err != nil || code != 0 || strings.TrimSpace(out) != cwd {
		t.Fatalf("inherited cwd changed: output=%q code=%d error=%v", out, code, err)
	}
}

func TestInstallNFTPreflightSupportedStates(t *testing.T) {
	policy := reconcileTestPolicy()
	owned := nftListingFromRulesBodyForTest(policy.rules, 20)
	legacy := policy.rules
	for _, role := range nftManagedRoles {
		legacy = strings.ReplaceAll(legacy, ` comment "`+nftOwnershipPrefix+`v1:`+role+`"`, "")
	}
	for _, tc := range []struct {
		name, live, missing string
		code                int
	}{
		{"current install", wrapNFTListingForTest(owned), "", 0},
		{"harmless foreign UID", wrapNFTListingForTest("meta skuid 12345 accept # handle 10\n" + owned), "", 0},
		{"legacy upgrade", wrapNFTListingForTest(nftListingFromRulesBodyForTest(legacy, 20)), "", 0},
		{"empty managed chain", wrapNFTListingForTest(""), "", 0},
		{"missing chain", "No such file or directory", "", 1},
		{"new proxy identity", "No such file or directory", defaultProxyUser, 1},
		{"new agent identity", "No such file or directory", defaultAgentUser, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, out := newFakeEnv(t)
			src := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(src, []byte("mode: balanced\nforward_proxy:\n  enabled: true\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runner.on(argvFor(env.nftPath, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), tc.live, tc.code, nil)
			lookup := env.lookupUser
			env.lookupUser = func(name string) (*user.User, error) {
				if name == tc.missing {
					return nil, user.UnknownUserError(name)
				}
				return lookup(name)
			}
			env.mkdirAll = func(string, os.FileMode) error { t.Fatal("dry-run mkdir"); return nil }
			env.writeFile = func(string, []byte, os.FileMode) error { t.Fatal("dry-run write"); return nil }
			env.chmod = func(string, os.FileMode) error { t.Fatal("dry-run chmod"); return nil }
			env.chown = func(string, int, int) error { t.Fatal("dry-run chown"); return nil }
			if err := runInstall(t.Context(), env, installOpts{dryRun: true, configSource: src}); err != nil {
				t.Fatal(err)
			}
			if deferred := strings.Contains(out.String(), "[DEFERRED] nft reconciliation:"); deferred != (tc.missing != "") {
				t.Fatalf("identity deferral=%v, output=%s", deferred, out.String())
			}
			assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
		})
	}
}

func TestInstallNFTPreflightReadFailures(t *testing.T) {
	for _, name := range []string{"rules unreadable", "config unreadable", "nft unavailable", "identity unavailable", "invalid UID"} {
		t.Run(name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			src := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(src, []byte("mode: balanced\nforward_proxy:\n  enabled: true\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			read, lookup := env.readFile, env.lookupUser
			want := ""
			switch name {
			case "rules unreadable", "config unreadable":
				path := env.nftRulesPath
				want = "read " + path
				if name == "config unreadable" {
					path, want = src, "read prospective managed config"
				}
				reads := 0
				env.readFile = func(p string) ([]byte, error) {
					if p == path {
						reads++
						if name != "config unreadable" || reads > 1 {
							return nil, os.ErrPermission
						}
					}
					return read(p)
				}
			case "nft unavailable":
				want = "list nft managed chain"
				runner.on(argvFor(env.nftPath, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", -1, os.ErrNotExist)
			case "identity unavailable", "invalid UID":
				want = "lookup " + env.agentUserName
				if name == "invalid UID" {
					want = "parse agent uid"
				}
				env.lookupUser = func(n string) (*user.User, error) {
					if n == env.agentUserName {
						if name == "invalid UID" {
							return &user.User{Uid: "invalid"}, nil
						}
						return nil, errors.New("identity service unavailable")
					}
					return lookup(n)
				}
			}
			if err := runInstall(t.Context(), env, installOpts{dryRun: true, configSource: src}); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error=%v, want refusal containing %q", err, want)
			}
			assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
		})
	}
}

func TestInstallNFTPreflightUsesProspectiveConfig(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	policy := reconcileTestPolicy()
	live := wrapNFTListingForTest("ip daddr 127.0.0.1 tcp dport 9000 accept # handle 10\n" + nftListingFromRulesBodyForTest(policy.rules, 20))
	runner.on(argvFor(env.nftPath, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), live, 0, nil)
	src := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(src, []byte("forward_proxy:\n  enabled: true\ncontainment:\n  agent_listener: 127.0.0.1:9000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preflightInstallNFTRules(t.Context(), env, src); err == nil || !strings.Contains(err.Error(), "bypass the managed listener guard") {
		t.Fatalf("prospective listener guard not planned: %v", err)
	}
	assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
}

func TestInstallNFTRulesPolicyValidationErrors(t *testing.T) {
	for _, tc := range []struct {
		name, data, want string
	}{
		{"operator unavailable", "", "lookup operator user"},
		{"invalid listener", "containment:\n  agent_listener: invalid\n", "managed listener config"},
		{"invalid loopback services", "containment:\n  loopback_services: false\n", "managed config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			if tc.name == "operator unavailable" {
				lookup := env.lookupUser
				env.lookupUser = func(name string) (*user.User, error) {
					if name == env.operatorUser {
						return nil, errors.New("operator unavailable")
					}
					return lookup(name)
				}
			}
			_, err := installNFTRulesPolicy(env, nftReconcileObservation{}, []byte(tc.data), time.Now())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid policy error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestInstallNFTPreflightReobservesAfterUserCreation(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	src := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(src, []byte("mode: balanced\nforward_proxy:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lookup := env.lookupUser
	env.lookupUser = func(name string) (*user.User, error) {
		if name == env.proxyUserName || name == env.agentUserName {
			return nil, user.UnknownUserError(name)
		}
		return lookup(name)
	}
	if err := preflightInstallNFTRules(t.Context(), env, src); err != nil || !strings.Contains(out.String(), "[DEFERRED]") {
		t.Fatalf("clean install preflight: error=%v output=%s", err, out.String())
	}
	// Simulate useradd completing and a conflicting rule appearing before apply.
	env.lookupUser = lookup
	policy := reconcileTestPolicy()
	live := wrapNFTListingForTest("meta skuid 987 accept # handle 10\n" + nftListingFromRulesBodyForTest(policy.rules, 20))
	runner.on(argvFor(env.nftPath, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), live, 0, nil)
	changed, err := stepInstallNFTRulesApply(t.Context(), env)
	if changed || err == nil || !strings.Contains(err.Error(), "nft reconciliation conflict:") {
		t.Fatalf("apply reused stale preflight: changed=%v error=%v", changed, err)
	}
	if _, err := os.Stat(env.nftRulesPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused apply wrote managed rules: %v", err)
	}
	assertNoServiceOrNFTMutationAfterPreflightFailure(t, runner)
}

func TestDoctorNodeProxyProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux diagnostic process context")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	run := defaultDoctorEnv().runCmd
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	out, code, err := run(ctx, node, "-p", `process.allowedNodeEnvironmentFlags.has('--use-env-proxy')`)
	if err != nil || code != 0 || strings.TrimSpace(out) != "true" {
		t.Skip("node does not support the installed runtime contract's NODE_USE_ENV_PROXY fallback")
	}
	for _, tc := range []struct {
		name, status, class string
		proxyStatus         int
		closed              bool
	}{
		{"success", statusPass, classNone, http.StatusOK, false},
		{"policy response", statusFail, classPolicy, http.StatusServiceUnavailable, false},
		{"connection failure", statusFail, classProxyCompat, http.StatusOK, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodConnect {
					w.WriteHeader(tc.proxyStatus)
					return
				}
				conn, rw, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Errorf("proxy hijack: %v", err)
					return
				}
				defer func() { _ = conn.Close() }()
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Errorf("proxy deadline: %v", err)
					return
				}
				if _, err := io.WriteString(rw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
					t.Errorf("proxy connect: %v", err)
					return
				}
				if err := rw.Flush(); err != nil {
					t.Errorf("proxy flush: %v", err)
					return
				}
				req, err := http.ReadRequest(rw.Reader)
				if err != nil {
					t.Errorf("proxy request: %v", err)
					return
				}
				_ = req.Body.Close()
				_, _ = fmt.Fprintf(rw, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", tc.proxyStatus, http.StatusText(tc.proxyStatus))
				_ = rw.Flush()
			}))
			t.Cleanup(proxy.Close)
			if tc.closed {
				proxy.Close()
			}
			dir := t.TempDir()
			shim := filepath.Join(dir, "shim.cjs")
			if err := os.WriteFile(shim, []byte(renderUndiciShim()), 0o600); err != nil {
				t.Fatal(err)
			}
			wrapper := filepath.Join(dir, "pipelock-node")
			// Isolate the child environment and use only the local test proxy.
			body := "#!/bin/sh\nexec env -i NODE_USE_ENV_PROXY=1 HTTP_PROXY=" + shellQuote(proxy.URL) + " HTTPS_PROXY=" + shellQuote(proxy.URL) + " " + shellQuote(node) + " --require " + shellQuote(shim) + " \"$@\"\n"
			if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil { //nolint:gosec // G306: executable wrapper fixture in a temporary directory.
				t.Fatal(err)
			}
			operatorDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(operatorDir, "package.json"), []byte("invalid json"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Chdir(operatorDir)
			env := defaultDoctorEnv()
			env.wrapperDir, env.undiciShimPath, env.canaryURL = dir, shim, "http://api.vendor.example/"
			// Replace sudo so the test needs no privileged identity switch;
			// retain the real wrapper, Node process, and command runner.
			env.runCmd = func(ctx context.Context, _ string, args ...string) (string, int, error) {
				return run(ctx, args[4], args[5:]...)
			}
			result := checkNodeThroughProxy(ctx, env)
			if result.status != tc.status || result.class != tc.class {
				t.Fatalf("doctor node result=%+v", result)
			}
			if !tc.closed && requests.Load() == 0 {
				t.Fatal("node did not reach the proxy")
			}
		})
	}
}
