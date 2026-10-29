// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReloadDoorwaysPrecedeConfigErrors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configErr error
		data      string
	}{
		{name: "unreadable config", configErr: os.ErrPermission},
		{name: "malformed config", data: "containment: ["},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			env := reconcileRegressionEnv()
			read := env.readFile
			env.configPath = "/managed/config.yaml"
			env.readFile = func(path string) ([]byte, error) {
				if path == env.configPath {
					return []byte(tc.data), tc.configErr
				}
				return read(path)
			}
			env.reconcileForwarders = func(context.Context, int, []config.ContainmentLoopbackService) error { called = true; return nil }
			err := reloadNFTRules(context.Background(), env)
			t.Logf("reload error=%v; doorway reconciliation called=%v", err, called)
			if err == nil || !called {
				t.Fatal("config error skipped revocation")
			}
		})
	}
}

func reconcileRegressionEnv() *nftReloadEnv {
	rules := renderNFTRules(1000, 967, 966, 8888, defaultNFTTable, defaultNFTChain)
	return &nftReloadEnv{
		nftPath: "nft", rulesPath: "/managed/rules.nft", table: defaultNFTTable, chain: defaultNFTChain,
		readFile: func(path string) ([]byte, error) {
			if path == "/managed/rules.nft" {
				return []byte(rules), nil
			}
			return nil, os.ErrNotExist
		},
		writeFile:  func(string, []byte, os.FileMode) error { return errors.New("unexpected write") },
		removeFile: func(string) error { return nil },
		runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
			if strings.Contains(strings.Join(args, " "), "list chain") {
				return legacyManagedBlockWithHandles(40), 0, nil
			}
			return "", 1, fmt.Errorf("unexpected command %v", args)
		},
	}
}

func TestReloadDoorwaysPrecedeNFTFailures(t *testing.T) {
	for _, stage := range []string{"list", "validate", "apply", "persist", "doorway"} {
		t.Run(stage, func(t *testing.T) {
			env := reconcileRegressionEnv()
			env.configPath = "/managed/config.yaml"
			read := env.readFile
			configReads := 0
			env.readFile = func(path string) ([]byte, error) {
				if path == env.configPath {
					configReads++
					return []byte(loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 9200, expiredLoopbackTestStamp))), nil
				}
				data, err := read(path)
				if stage == "persist" {
					data = append(data, []byte("# stale file\n")...)
				}
				return data, err
			}
			loopback, published := 0, 0
			failure := errors.New("injected " + stage + " failure")
			env.reconcileForwarders = func(_ context.Context, _ int, services []config.ContainmentLoopbackService) error {
				loopback++
				if len(services) != 0 {
					t.Fatal("expired service retained")
				}
				if stage == "doorway" {
					return failure
				}
				return nil
			}
			env.reconcilePublished = func(context.Context, []config.ContainmentPublishedService) error { published++; return nil }
			env.writeFile = func(string, []byte, os.FileMode) error {
				if stage == "persist" {
					return failure
				}
				return nil
			}
			env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
				command := strings.Join(args, " ")
				if strings.Contains(command, "list chain") {
					if stage == "list" {
						return "", 1, failure
					}
					return "", 0, nil
				}
				if (stage == "validate" && strings.HasPrefix(command, "-c")) || (stage == "apply" && args[0] == "-f") {
					return "", 1, failure
				}
				return "", 0, nil
			}
			err := reloadNFTRules(context.Background(), env)
			if !errors.Is(err, failure) {
				t.Fatalf("error=%v; want %v", err, failure)
			}
			if loopback != 1 || published != 1 || configReads != 1 {
				t.Fatalf("loopback=%d published=%d config reads=%d; want one each", loopback, published, configReads)
			}
		})
	}
}

func TestReloadBrokenConfigStopsInstalledExpiredDoorway(t *testing.T) {
	for _, mode := range []string{"unreadable", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			installed, runner, _ := newFakeEnv(t)
			services := []config.ContainmentLoopbackService{loopbackTestService(9200)}
			if _, err := stepInstallNetworkNamespaceWithServices(&services).apply(context.Background(), installed); err != nil {
				t.Fatal(err)
			}
			// The recorded grant has now lapsed while the managed config is broken.
			inv, err := readLoopbackForwarderInventory(installed)
			if err != nil {
				t.Fatal(err)
			}
			inv.Services[0].ExpiresAt = expiredLoopbackTestStamp
			data, err := json.Marshal(inv)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(installed.loopbackForwarderInvPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			base := loopbackForwarderUnitBase("127.0.0.1", 9200)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			agent, forwarded := net.Pipe()
			defer func() { _ = agent.Close() }()
			done := make(chan error, 1)
			target := newDoorwayEcho(t)
			go func() { done <- proxyOneNetnsConn(ctx, forwarded, "unix", target) }()
			if err := agent.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := agent.Write([]byte("live")); err != nil {
				t.Fatal(err)
			}
			echo := make([]byte, 4)
			if _, err := io.ReadFull(agent, echo); err != nil {
				t.Fatal(err)
			}
			if string(echo) != "live" {
				t.Fatalf("positive control echo=%q", echo)
			}
			run := installed.runCmd
			stopped := false
			installed.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if name == "systemctl" && strings.Join(args, " ") == "stop "+base+".service" {
					stopped = true
					cancel()
				}
				return run(ctx, name, args...)
			}
			env := reconcileRegressionEnv()
			env.configPath = "/managed/config.yaml"
			read := env.readFile
			env.readFile = func(path string) ([]byte, error) {
				if path == env.configPath {
					if mode == "unreadable" {
						return nil, os.ErrPermission
					}
					return []byte("containment: ["), nil
				}
				return read(path)
			}
			env.reconcileForwarders = func(ctx context.Context, _ int, desired []config.ContainmentLoopbackService) error {
				_, err := stepInstallNetworkNamespaceWithServices(&desired).apply(ctx, installed)
				return err
			}
			if err := reloadNFTRules(context.Background(), env); err == nil {
				t.Fatal("broken config must still be reported")
			}
			if !stopped || !runnerCalled(runner, "disable --now "+base+"-netns.service") || !runnerCalled(runner, "disable --now "+base+".socket") {
				t.Fatal("revocation did not stop listener, socket and established relay")
			}
			if _, err := agent.Read(echo); err == nil {
				t.Fatal("established relay survived revocation")
			}
			select {
			case relayErr := <-done:
				_ = relayErr // revocation cancels the relay; only its exit is asserted
			case <-time.After(5 * time.Second):
				t.Fatal("revoked relay did not exit")
			}
			inv, err = readLoopbackForwarderInventory(installed)
			if err != nil || len(inv.Services) != 0 {
				t.Fatalf("inventory after revocation=%+v, %v", inv, err)
			}
		})
	}
}

func TestNFTHoleSeverityPrecedence(t *testing.T) {
	stale := `meta skuid 987 oifname "lo" ip daddr 127.0.0.1 socket cgroupv2 level 1 "pipelock_contained.slice" ct state new ct mark set 0x504c4b01 accept # handle 70`
	for _, rule := range []string{"meta skuid 987 accept", "meta skuid 987 tcp dport 443 accept", "meta skuid 987 ip daddr 0.0.0.0/0 accept", "missing drop"} {
		t.Run(rule, func(t *testing.T) {
			live := strings.Replace(goodNFTContainmentOutput, "meta skuid 987 drop", stale+"\nmeta skuid 987 drop", 1)
			if rule == "missing drop" {
				live = strings.Replace(live, "meta skuid 987 drop", "", 1)
			} else {
				live = strings.Replace(live, "meta skuid 987 drop", rule+"\nmeta skuid 987 drop", 1)
			}
			env := makeProbeEnv(t)
			env.operatorUser = testOperatorUser
			env.lookupUser = containTestLookup
			env.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
			env.runCmd = func(context.Context, string, ...string) (string, int, error) { return live, 0, nil }
			status, detail := probeNFTContainment(context.Background(), env)
			if status != statusFail || !strings.Contains(detail, containmentHoleDetailPrefix) {
				t.Fatalf("verify=%s %s", status, detail)
			}
			result := doctorChainStructureReader(env, &doctorEnv{port: env.port, agentUserName: env.agentUserName})(context.Background())
			if result.status != statusFail || !strings.Contains(result.detail, containmentHoleDetailPrefix) {
				t.Fatalf("doctor=%+v", result)
			}
		})
	}
}

func TestNFTRollbackPreservesExistingTimerOnInterruption(t *testing.T) {
	for _, boundary := range []string{"file restore", "daemon reload", "timer enable", "timer start", "unknown prior state"} {
		t.Run(boundary, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			env.prevNFTExpiryTimerStateKnown = boundary != "unknown prior state"
			env.prevNFTExpiryTimerEnabled = env.prevNFTExpiryTimerStateKnown
			env.prevNFTExpiryTimerActive = env.prevNFTExpiryTimerStateKnown
			if boundary == "file restore" {
				env.nftRulesWrittenByInstall = true
				env.removeFile = func(string) error { return errors.New("interrupted") }
			}
			failArgs := map[string][]string{
				"daemon reload": {"daemon-reload"},
				"timer enable":  {"enable", filepath.Base(env.nftExpiryTimerPath)},
				"timer start":   {"start", filepath.Base(env.nftExpiryTimerPath)},
			}[boundary]
			if len(failArgs) > 0 {
				runner.on(argvFor("systemctl", failArgs...), "", 1, errors.New("interrupted"))
			}

			held := false
			env.reconcileLockPath = "/managed/reconcile.lock"
			env.lockFn = func(_ string, fn func() error) error { held = true; defer func() { held = false }(); return fn() }
			run := env.runCmd
			env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if !held {
					t.Fatal("rollback command outside reconcile lock")
				}
				return run(ctx, name, args...)
			}
			err := stepInstallNFTRulesUndo(context.Background(), env)
			if boundary != "unknown prior state" && (err == nil || !strings.Contains(err.Error(), "interrupted")) {
				t.Fatalf("boundary %s was not exercised: %v", boundary, err)
			}
			if runnerCalled(runner, "disable --now "+filepath.Base(env.nftExpiryTimerPath)) || runnerCalled(runner, "stop "+filepath.Base(env.nftExpiryServicePath)) {
				t.Fatal("rollback interrupted periodic repair")
			}
		})
	}
}

func TestDefiniteAgentAcceptExpressions(t *testing.T) {
	for _, tc := range []struct {
		rule string
		want bool
	}{
		{"", false},
		{"meta skuid 988 tcp dport 443 accept", false},
		{"meta skuid 987 tcp dport 443 accept", true},
		{"meta skuid 987 tcp dport 0 accept", false},
		{"meta skuid 987 ip daddr invalid accept", false},
		{"meta skuid 987 ip daddr 192.0.2.1 accept", true},
		{"meta skuid 987 ip daddr 192.0.2.0/24 accept", true},
		{"meta skuid 987 ip6 daddr ::/0 accept", true},
		{"meta skuid 987 ip6 daddr ::1 tcp dport 443 accept", true},
		{"meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept", false},
		{"meta skuid 987 ip daddr 127.0.0.1/32 tcp dport 8888 accept", false},
		{"meta skuid 987 ip daddr ::1 tcp dport 443 accept", false},
		{"meta skuid 987 ip6 daddr 192.0.2.1 tcp dport 443 accept", false},
		{"meta skuid 987 ip saddr 127.0.0.2 ip daddr 127.0.0.1 tcp dport 8888 accept", false},
		{"meta skuid 987 ip daddr 192.0.2.1 drop", false},
		{"meta skuid 987 ip daddr 192.0.2.1 ct state new accept", false},
		{"meta skuid 987 ip daddr 192.0.2.1 accept counter", false},
		{"meta skuid 987 tcp dport 443 counter packets 0 bytes 0 accept comment \"operator\" # handle 8", true},
	} {
		t.Run(tc.rule, func(t *testing.T) {
			if got := lineHasDefiniteAgentAccept(tc.rule, 987, 8888); got != tc.want {
				t.Fatalf("definite accept=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestNFTRollbackRestoresRuntimeTimerBeforePersistentCleanup(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(fmt.Sprint(denied), func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			env.prevNFTExpiryTimerStateKnown = true
			env.prevNFTExpiryTimerEnabled = true
			env.prevNFTExpiryTimerEnabledRuntime = true
			env.prevNFTExpiryTimerActive = true
			env.nftTimerEnableAttempted = true
			timer := filepath.Base(env.nftExpiryTimerPath)
			if denied {
				runner.on(argvFor("systemctl", "disable", timer), "cleanup denied", 1, nil)
			}
			err := stepInstallNFTRulesUndo(context.Background(), env)
			if denied && (err == nil || !strings.Contains(err.Error(), "remove persistent")) {
				t.Fatalf("cleanup failure=%v", err)
			}
			if !denied && err != nil {
				t.Fatal(err)
			}
			runtimeLink, persistentCleanup := -1, -1
			for i, call := range runner.calls {
				if strings.Join(call.args, " ") == "enable --runtime "+timer {
					runtimeLink = i
				}
				if strings.Join(call.args, " ") == "disable "+timer {
					persistentCleanup = i
				}
			}
			if runtimeLink < 0 || persistentCleanup <= runtimeLink {
				t.Fatal("persistent link removed before runtime link restored")
			}
			if runnerCalled(runner, "disable --now "+timer) {
				t.Fatal("active timer stopped")
			}
		})
	}
}

func TestNFTRollbackRefusesUnavailableDefaultLock(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.reconcileLockPath = filepath.Join(t.TempDir(), "missing-parent", "reconcile.lock")
	env.lockFn = nil
	if err := stepInstallNFTRulesUndo(context.Background(), env); err == nil {
		t.Fatal("rollback continued without reconcile lock")
	}
	if len(runner.calls) != 0 {
		t.Fatal("rollback changed system state before acquiring lock")
	}
}

func TestNFTRollbackReportsActiveDisabledTimerCleanupFailure(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.prevNFTExpiryTimerStateKnown = true
	env.prevNFTExpiryTimerActive = true
	timer := filepath.Base(env.nftExpiryTimerPath)
	runner.on(argvFor("systemctl", "disable", timer), "cleanup denied", 1, nil)
	err := stepInstallNFTRulesUndo(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "disabled state") {
		t.Fatalf("disable failure=%v", err)
	}
	if !runnerCalled(runner, "start "+timer) || runnerCalled(runner, "disable --now "+timer) {
		t.Fatal("active repair timer was interrupted")
	}
}
