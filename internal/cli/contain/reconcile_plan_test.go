// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func reconcileTestPolicy() nftReconcilePolicy {
	return nftReconcilePolicy{
		rules: renderNFTRules(1000, 988, 987, 8888, defaultNFTTable, defaultNFTChain),
		uids:  nftRulesHeaderUIDs{operatorUID: 1000, proxyUID: 988, agentUID: 987, proxyPort: 8888}, table: defaultNFTTable, chain: defaultNFTChain,
	}
}

func TestReconcilePlanOwnedRules(t *testing.T) {
	policy := reconcileTestPolicy()
	owned := strings.Split(nftListingFromRulesBodyForTest(policy.rules, 20), "\n")
	foreign := `meta skuid 12345 accept comment "operator rule" # handle 10`
	tests := []struct {
		name   string
		lines  []string
		change bool
	}{
		{"exact", owned, false},
		{"missing chain", nil, true},
	}
	for i := range owned {
		missing := append(slices.Clone(owned[:i]), owned[i+1:]...)
		duplicate := append(slices.Clone(owned), strings.Replace(owned[i], "# handle "+itoa(20+i), "# handle 90", 1))
		reordered := slices.Clone(owned)
		j := (i + 1) % len(owned)
		reordered[i], reordered[j] = reordered[j], reordered[i]
		tests = append(tests, struct {
			name   string
			lines  []string
			change bool
		}{fmt.Sprintf("missing/%d", i), missing, true},
			struct {
				name   string
				lines  []string
				change bool
			}{fmt.Sprintf("duplicate/%d", i), duplicate, true},
			struct {
				name   string
				lines  []string
				change bool
			}{fmt.Sprintf("reordered/%d", i), reordered, true})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			live := strings.Join(append([]string{foreign}, tc.lines...), "\n")
			if len(tc.lines) == 0 {
				live = ""
			}
			plan := planNFTReconciliation(policy, nftReconcileObservation{persisted: policy.rules, live: live})
			if plan.err() != nil || plan.kernelChanged != tc.change {
				t.Fatalf("plan=%+v error=%v", plan, plan.err())
			}
			if !tc.change {
				if plan.script != "" {
					t.Fatal("no-op emits transaction")
				}
				return
			}
			if strings.Contains(plan.script, "handle 10\n") {
				t.Fatal("foreign rule selected for deletion")
			}
			applied, err := applyNFTScriptForTest(live, plan.script)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkNFTReconciliationResult(policy, plan, applied); err != nil {
				t.Fatal(err)
			}
			if next := planNFTReconciliation(policy, nftReconcileObservation{persisted: policy.rules, live: applied}); next.kernelChanged || next.err() != nil {
				t.Fatalf("second run=%+v", next)
			}
		})
	}
}

func TestReconcilePlanLegacyConflicts(t *testing.T) {
	policy := reconcileTestPolicy()
	owned := nftListingFromRulesBodyForTest(policy.rules, 100)
	legacy := strings.Split(owned, "\n")
	for i, line := range legacy {
		fields := nftLineFields(line)
		legacy[i] = strings.Join(fields[:len(fields)-2], " ") + " # handle " + itoa(20+i)
	}
	tests := []struct {
		name, live string
		conflict   bool
	}{
		{"complete", strings.Join(legacy, "\n"), false},
		{"complete plus owned", strings.Join(legacy, "\n") + "\n" + owned, false},
		{"missing proxy allow followed by owned", strings.Join(append(slices.Clone(legacy[:2]), legacy[3:]...), "\n") + "\n" + owned, true},
		{"revoked service fragment", `meta skuid 987 ip daddr 127.0.0.1 tcp dport 9200 accept # handle 10` + "\n" + owned, true},
		{"standalone mark", `meta skuid 987 oifname "lo" ip daddr 127.0.0.1 socket cgroupv2 level 1 "pipelock_contained.slice" ct state new ct mark set 0x504c4b01 accept # handle 10` + "\n" + owned, true},
		{"unknown owner version", strings.Replace(owned, "pipelock:contain:v1:", "pipelock:contain:v2:", 1), true},
		{"duplicate handle", strings.Replace(owned, "# handle 101", "# handle 100", 1), true},
		{"foreign ownership on legacy", strings.Replace(strings.Join(legacy, "\n"), "accept # handle 20", `accept comment "operator" # handle 20`, 1), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := planNFTReconciliation(policy, nftReconcileObservation{persisted: policy.rules, live: tc.live})
			if (plan.err() != nil) != tc.conflict {
				t.Fatalf("plan error=%v", plan.err())
			}
			if tc.conflict {
				if plan.script != "" || !strings.Contains(plan.err().Error(), "handle ") || !strings.Contains(plan.err().Error(), "nft delete rule") {
					t.Fatalf("imprecise conflict: %+v", plan)
				}
				return
			}
			if !plan.kernelChanged {
				t.Fatal("legacy migration reported no change")
			}
			applied, err := applyNFTScriptForTest(tc.live, plan.script)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkNFTReconciliationResult(policy, plan, applied); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type reconcileModel struct {
	files          map[string]string
	live           string
	fail           string
	ackLost        bool
	applies, reads int
}

func newReconcileModel(live string) (*nftReloadEnv, *reconcileModel) {
	policy := reconcileTestPolicy()
	m := &reconcileModel{files: map[string]string{"/managed/rules.nft": policy.rules}, live: live}
	env := &nftReloadEnv{nftPath: "nft", rulesPath: "/managed/rules.nft", configPath: "/managed/config.yaml", table: policy.table, chain: policy.chain}
	env.readFile = func(path string) ([]byte, error) {
		if path == env.rulesPath && m.fail == "file-observe" && m.files[path] == policy.rules {
			return nil, os.ErrPermission
		}
		if path == env.configPath {
			m.reads++
		}
		data, ok := m.files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(data), nil
	}
	env.writeFile = func(path string, data []byte, _ os.FileMode) error {
		if m.fail == "persist" && path == env.rulesPath || m.fail == "script" && path == env.rulesPath+".reload" {
			return errors.New("injected write failure")
		}
		if m.fail == "file-mismatch" && path == env.rulesPath {
			return nil
		}
		m.files[path] = string(data)
		return nil
	}
	env.removeFile = func(path string) error { delete(m.files, path); return nil }
	env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
		if strings.HasPrefix(strings.Join(args, " "), "-n -a list chain") {
			if m.fail == "observe" && m.applies > 0 {
				return "", 1, errors.New("injected observation failure")
			}
			if m.live == "" {
				return "No such file or directory", 1, nil
			}
			return m.live, 0, nil
		}
		if args[0] == "-c" {
			if m.fail == "validate" {
				return "", 1, errors.New("injected validation failure")
			}
			return "", 0, nil
		}
		m.applies++
		if m.fail == "apply" {
			return "", 1, errors.New("injected apply failure")
		}
		if m.fail != "mismatch" {
			var err error
			m.live, err = applyNFTScriptForTest(m.live, m.files[args[1]])
			if err != nil {
				return "", 1, err
			}
		}
		if m.ackLost {
			return "", 1, errors.New("lost acknowledgement")
		}
		return "", 0, nil
	}
	return env, m
}

func TestReconcileRetryAndPostObservation(t *testing.T) {
	policy := reconcileTestPolicy()
	for _, boundary := range []string{"persist", "script", "validate", "apply", "observe", "file-observe", "file-mismatch", "lost acknowledgement", "mismatch"} {
		t.Run(boundary, func(t *testing.T) {
			env, m := newReconcileModel("")
			// A stale file forces the persistence boundary as well as kernel work.
			m.files[env.rulesPath] += "# stale\n"
			m.fail = boundary
			m.ackLost = boundary == "lost acknowledgement"
			if err := reloadNFTRules(context.Background(), env); err == nil {
				t.Fatal("injected failure reported success")
			}
			commits := m.applies
			m.fail = ""
			m.ackLost = false
			if err := reloadNFTRules(context.Background(), env); err != nil {
				t.Fatal(err)
			}
			if boundary == "lost acknowledgement" || boundary == "observe" {
				if m.applies != commits {
					t.Fatal("retry duplicated an acknowledged-by-observation commit")
				}
			}
			plan := planNFTReconciliation(policy, nftReconcileObservation{persisted: m.files[env.rulesPath], live: m.live})
			if plan.kernelChanged || plan.fileChanged || plan.err() != nil {
				t.Fatalf("retry did not converge: %+v", plan)
			}
			commits = m.applies
			if err := reloadNFTRules(context.Background(), env); err != nil || commits != m.applies {
				t.Fatalf("second run not a no-op: %v", err)
			}
		})
	}
}

func TestReconcileHeaderFailureStillClosesDoorways(t *testing.T) {
	for _, header := range []string{"unreadable", "missing", "corrupt", "overlap", "negative"} {
		t.Run(header, func(t *testing.T) {
			env, _ := newReconcileModel("")
			read := env.readFile
			env.readFile = func(path string) ([]byte, error) {
				if path == env.rulesPath {
					switch header {
					case "unreadable":
						return nil, os.ErrPermission
					case "missing":
						return nil, nil
					case "overlap":
						return []byte("# operator=987 pipelock-proxy=988 pipelock-agent=987 proxy-port=8888"), nil
					case "negative":
						return []byte("# operator=-1 pipelock-proxy=988 pipelock-agent=987 proxy-port=8888"), nil
					default:
						return []byte("# operator=bad pipelock-proxy=988 pipelock-agent=987"), nil
					}
				}
				return read(path)
			}
			closed := 0
			env.reconcileForwarders = func(_ context.Context, port int, services []config.ContainmentLoopbackService) error {
				if port != 0 || len(services) != 0 {
					t.Fatal("unknown header grants a doorway")
				}
				closed++
				return nil
			}
			env.reconcilePublished = func(_ context.Context, services []config.ContainmentPublishedService) error {
				if len(services) != 0 {
					t.Fatal("unknown header grants a publication")
				}
				closed++
				return nil
			}
			if err := reloadNFTRules(context.Background(), env); err == nil || closed != 2 {
				t.Fatalf("error=%v cleanup=%d", err, closed)
			}
		})
	}
}

func TestReconcileInventoryFailureClosesKnownUnits(t *testing.T) {
	for _, kind := range []string{"loopback", "published"} {
		for _, failure := range []string{"unreadable", "corrupt"} {
			t.Run(kind+"/"+failure, func(t *testing.T) {
				env, runner, _ := newFakeEnv(t)
				dir := filepath.Dir(env.proxyForwarderSocketPath)
				if err := os.MkdirAll(dir, 0o750); err != nil {
					t.Fatal(err)
				}
				var units []string
				path := env.loopbackForwarderInvPath
				var run func() (bool, error)
				if kind == "loopback" {
					svc := loopbackTestService(9200)
					base := loopbackForwarderUnitBase(svc.Host, svc.Port)
					files := map[string]string{base + ".socket": renderDeclaredLoopbackSocketUnit(env.agentUserName, svc), base + ".service": renderDeclaredLoopbackForwarderUnit(env.pipelockTarget, env.proxyUserName, svc), base + "-netns.service": renderDeclaredLoopbackNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, svc)}
					for name, body := range files {
						if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
							t.Fatal(err)
						}
						units = append(units, name)
					}
					empty := []config.ContainmentLoopbackService{}
					run = func() (bool, error) {
						return stepInstallNetworkNamespaceWithServices(&empty).apply(context.Background(), env)
					}
				} else {
					svc := config.ContainmentPublishedService{Name: "viewer", AgentHost: "127.0.0.1", AgentPort: 9200, HostSocket: "/run/pipelock-published/viewer.sock", HostListen: "127.0.0.1:9201", OperatorUser: containInstallOperatorUser}
					for _, file := range publishedServiceFiles(dir, env.pipelockTarget, env.proxyUserName, svc) {
						if err := os.WriteFile(file.path, []byte(file.body), 0o600); err != nil {
							t.Fatal(err)
						}
						units = append(units, filepath.Base(file.path))
					}
					path = publishedServiceRecordPath(path)
					empty := []config.ContainmentPublishedService{}
					run = func() (bool, error) { return stepInstallPublishedServices(&empty).apply(context.Background(), env) }
				}
				read := env.readFile
				env.readFile = func(p string) ([]byte, error) {
					if p == path {
						if failure == "unreadable" {
							return nil, os.ErrPermission
						}
						return []byte("{"), nil
					}
					return read(p)
				}
				if _, err := run(); err == nil {
					t.Fatal("inventory error hidden")
				}
				for _, unit := range units {
					command := "stop " + unit
					if strings.HasSuffix(unit, ".socket") || strings.HasSuffix(unit, "-netns.service") {
						command = "disable --now " + unit
					}
					if !runnerCalled(runner, command) {
						t.Fatalf("known unit survived: %s", command)
					}
				}
			})
		}
	}
}

func TestReconcileRemedyMatchesReloadAndInstall(t *testing.T) {
	policy := reconcileTestPolicy()
	lines := strings.Split(nftListingFromRulesBodyForTest(policy.rules, 20), "\n")
	live := strings.Join(append(slices.Clone(lines[:2]), lines[3:]...), "\n")
	env, m := newReconcileModel(live)
	probe := makeProbeEnv(t, func(p *probeEnv) {
		p.lookupUser = containTestLookup
		p.nftRulesPath = env.rulesPath
		p.configPath = env.configPath
		p.readFile = env.readFile
		p.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return wrapNFTListingForTest(m.live), 0, nil
		}
	})
	current := containmentUIDs{operatorUID: 1000, operatorKnown: true, proxyUID: 988, agentUID: 987}
	predicted, remedy, err := predictNFTReconciliation(probe, live, current)
	if err != nil || remedy != nftReloadRemedy || !predicted.kernelChanged {
		t.Fatalf("prediction=%+v remedy=%s error=%v", predicted, remedy, err)
	}
	status, detail := probeNFTContainment(context.Background(), probe)
	if status != statusFail || !strings.Contains(detail, nftReloadRemedy) {
		t.Fatalf("verify=(%s,%s)", status, detail)
	}
	doctor := &doctorEnv{port: 8888, agentUserName: defaultAgentUser}
	if result := doctorChainStructureReader(probe, doctor)(context.Background()); result.status != statusFail || result.remediation != nftReloadRemedy {
		t.Fatalf("doctor=%+v", result)
	}
	var reloadScript string
	write := env.writeFile
	env.writeFile = func(path string, data []byte, mode os.FileMode) error {
		if path == env.rulesPath+".reload" {
			reloadScript = string(data)
		}
		return write(path, data, mode)
	}
	if err := reloadNFTRules(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if reloadScript != predicted.script {
		t.Fatal("reload executed a different plan than verify predicted")
	}
	if status, detail := probeNFTContainment(context.Background(), probe); status != statusPass {
		t.Fatalf("healthy timer result blocks verification: %s %s", status, detail)
	}
	installed, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(installed.nftRulesPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed.nftRulesPath, []byte(policy.rules), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", policy.table, policy.chain), wrapNFTListingForTest(live), 0, nil)
	var installScript string
	installWrite := installed.writeFile
	installed.writeFile = func(path string, data []byte, mode os.FileMode) error {
		if path == managedChainReloadPath(installed) {
			installScript = string(data)
		}
		return installWrite(path, data, mode)
	}
	if _, err := stepInstallNFTRules().apply(context.Background(), installed); err != nil {
		t.Fatal(err)
	}
	if installScript != reloadScript {
		t.Fatalf("install and reload executed different plans:\ninstall=%s\nreload=%s", installScript, reloadScript)
	}
}

func wrapNFTListingForTest(lines string) string {
	return "table inet " + defaultNFTTable + " {\n chain " + defaultNFTChain + " {\n type filter hook output priority filter; policy accept;\n" + lines + "\n }\n}\n"
}

func TestReconcileConflictIsUntouchedAndVerifyFails(t *testing.T) {
	policy := reconcileTestPolicy()
	live := `meta skuid 987 ip daddr 127.0.0.1 tcp dport 9200 accept # handle 10` + "\n" + nftListingFromRulesBodyForTest(policy.rules, 20)
	env, m := newReconcileModel(live)
	if err := reloadNFTRules(context.Background(), env); err == nil || !strings.Contains(err.Error(), "handle 10") {
		t.Fatalf("unowned fragment reload error=%v", err)
	}
	if m.live != live || m.applies != 0 || len(m.files) != 1 {
		t.Fatal("conflict mutated live or persisted state")
	}
	probe := makeProbeEnv(t, func(p *probeEnv) {
		p.lookupUser = containTestLookup
		p.nftRulesPath = env.rulesPath
		p.configPath = env.configPath
		p.readFile = env.readFile
		p.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return wrapNFTListingForTest(live), 0, nil
		}
	})
	if status, detail := probeNFTContainment(context.Background(), probe); status != statusFail || !strings.Contains(detail, "handle 10") {
		t.Fatalf("verify=%s %s", status, detail)
	}
}

func TestReconcileLegacyIdentityAndPositionBoundaries(t *testing.T) {
	for _, operator := range []int{0, 1000} {
		t.Run(itoa(operator), func(t *testing.T) {
			body := renderNFTRules(operator, 2001, 2002, 8888, defaultNFTTable, defaultNFTChain)
			var legacy []string
			for _, rule := range nftRulesWithHandles(nftListingFromRulesBodyForTest(body, 20)) {
				fields := nftLineFields(rule.line)
				legacy = append(legacy, strings.Join(fields[:len(fields)-2], " ")+" # handle "+itoa(rule.handle))
			}
			live := "meta skuid 12345 counter # handle 10\n" + strings.Join(legacy, "\n")
			if got := managedNFTBlockLength(nftRulesWithHandles(live), 1, operator, 2001, 2002); got != 6 {
				t.Fatalf("offset block length=%d", got)
			}
			if got := legacyManagedNFTRuleBlockHandles(live, operator, 2001, 2002); len(got) != 6 {
				t.Fatalf("identity handles=%v", got)
			}
			if script := renderNFTManagedChainReloadScript(live, body, defaultNFTTable, defaultNFTChain, operator, 2001, 2002, false); !strings.Contains(script, "handle 20") {
				t.Fatalf("identity migration=%s", script)
			}
		})
	}
}

func TestReconcileLegacyIdentityCrashUsesBackup(t *testing.T) {
	policy := reconcileTestPolicy()
	oldBody := renderNFTRules(1000, 988, 986, 8888, policy.table, policy.chain)
	for _, role := range nftManagedRoles {
		oldBody = strings.ReplaceAll(oldBody, ` comment "pipelock:contain:v1:`+role+`"`, "")
	}
	live := nftListingFromRulesBodyForTest(oldBody, 20)
	for _, consumer := range []string{"reload", "install", "prediction"} {
		t.Run(consumer, func(t *testing.T) {
			env, model := newReconcileModel(live)
			// Crash after backupAndWrite promoted the new identity, before apply.
			model.files[env.rulesPath+".bak"] = oldBody
			switch consumer {
			case "prediction":
				probe := makeProbeEnv(t, func(p *probeEnv) {
					p.nftRulesPath, p.configPath, p.readFile = env.rulesPath, env.configPath, env.readFile
				})
				current := containmentUIDs{operatorUID: 1000, operatorKnown: true, proxyUID: 988, agentUID: 987}
				plan, remedy, err := predictNFTReconciliation(probe, live, current)
				if err != nil || remedy != nftReloadRemedy || !plan.kernelChanged || plan.removed != 6 {
					t.Fatalf("backup recovery prediction: plan=%+v remedy=%s error=%v", plan, remedy, err)
				}
			case "install":
				installed, runner, _ := newFakeEnv(t)
				if err := os.MkdirAll(filepath.Dir(installed.nftRulesPath), 0o750); err != nil {
					t.Fatal(err)
				}
				for path, body := range map[string]string{installed.nftRulesPath: policy.rules, installed.nftRulesPath + ".bak": oldBody} {
					if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", policy.table, policy.chain), wrapNFTListingForTest(live), 0, nil)
				if _, err := stepInstallNFTRules().apply(context.Background(), installed); err != nil {
					t.Fatalf("install cannot recover changed identity: %v", err)
				}
			default:
				for i := 0; i < 2; i++ {
					if err := reloadNFTRules(context.Background(), env); err != nil {
						t.Fatalf("timer/boot retry %d cannot recover changed identity: %v", i, err)
					}
				}
				if model.applies != 1 || !lineHasManagedCatchAllDrop(nftRulesWithHandles(model.live)[5].line, policy.uids.agentUID) {
					t.Fatalf("new identity not enforced exactly once: applies=%d live=%s", model.applies, model.live)
				}
			}
		})
	}
}

func TestReconcilePostObservationDetectsForeignMutation(t *testing.T) {
	policy := reconcileTestPolicy()
	foreign := `meta skuid 12345 counter packets 1 bytes 4 # handle 10`
	// Use an owned drift alongside the foreign counter to establish ownership.
	live := foreign + "\n" + strings.Replace(nftListingFromRulesBodyForTest(policy.rules, 20), "tcp dport 8888", "tcp dport 8889", 1)
	before := planNFTReconciliation(policy, nftReconcileObservation{live: live})
	applied, err := applyNFTScriptForTest(live, before.script)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, after string
		fail        bool
	}{
		{"counter advanced", strings.Replace(applied, "packets 1 bytes 4", "packets 2 bytes 8", 1), false},
		{"foreign rule removed", strings.Replace(applied, foreign+"\n", "", 1), true},
		{"foreign expression changed", strings.Replace(applied, "skuid 12345", "skuid 12346", 1), true},
		{"owned rule missing", foreign, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkNFTReconciliationResult(policy, before, tc.after); (err != nil) != tc.fail {
				t.Fatalf("post-observation error=%v", err)
			}
		})
	}
}

func TestReconcilePublishedOwnershipBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, unit, body string
		want             bool
	}{
		{"foreign name", "operator.service", "", false},
		{"foreign extension", "pipelock-published-viewer.target", "", false},
		{"invalid name", "pipelock-published-!.service", "", false},
		{"foreign body", "pipelock-published-viewer.service", "[Service]\nExecStart=/bin/true\n", false},
		{"bad target", "pipelock-published-viewer.service", "bad-target", false},
		{"missing file", "pipelock-published-viewer.service", "missing", false},
		{"regular publication ending tcp", "pipelock-published-viewer-tcp.socket", "regular", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			dir := filepath.Dir(env.proxyForwarderSocketPath)
			body := tc.body
			if body == "regular" {
				body = renderPublishedSocketUnit(config.ContainmentPublishedService{Name: "viewer-tcp", OperatorUser: containInstallOperatorUser, HostSocket: "/run/pipelock-published/viewer-tcp.sock"})
			}
			if body == "bad-target" {
				body = strings.Replace(renderPublishedForwarderUnit(env.pipelockTarget, env.proxyUserName, config.ContainmentPublishedService{AgentPort: 9200}), "127.0.0.1:9200", "192.0.2.1:9200", 1)
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			if body != "missing" {
				if err := os.WriteFile(filepath.Join(dir, tc.unit), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := isManagedPublishedUnit(env, dir, tc.unit); got != tc.want {
				t.Fatalf("ownership=%v want %v", got, tc.want)
			}
		})
	}
}

func TestReconcileInventoryFailureStopsEstablishedRelay(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	services := []config.ContainmentLoopbackService{loopbackTestService(9200)}
	if _, err := stepInstallNetworkNamespaceWithServices(&services).apply(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agent, forwarded := net.Pipe()
	defer func() { _ = agent.Close() }()
	done := make(chan error, 1)
	target := newDoorwayEcho(t)
	go func() { done <- proxyOneNetnsConn(ctx, forwarded, "unix", target) }()
	// Use the existing revoked-doorway regression deadline.
	if err := agent.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(agent, buf); err != nil || string(buf) != "live" {
		t.Fatalf("positive control=%q,%v", buf, err)
	}
	run := env.runCmd
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if name == testSystemctl && strings.Join(args, " ") == "stop "+loopbackForwarderUnitBase("127.0.0.1", 9200)+".service" {
			cancel()
		}
		return run(ctx, name, args...)
	}
	read := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == env.loopbackForwarderInvPath {
			return nil, os.ErrPermission
		}
		return read(path)
	}
	empty := []config.ContainmentLoopbackService{}
	if _, err := stepInstallNetworkNamespaceWithServices(&empty).apply(context.Background(), env); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("inventory error=%v", err)
	}
	if _, err := agent.Read(buf); err == nil {
		t.Fatal("established relay survived revocation")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("revoked relay did not exit")
	}
}

func TestReconcileHealthyTimerDoesNotBlockLaunchEvidence(t *testing.T) {
	policy := reconcileTestPolicy()
	env, m := newReconcileModel(nftListingFromRulesBodyForTest(policy.rules, 20))
	probe := allPassEnv(t)
	run := probe.runCmd
	probe.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if name == testNFT {
			return wrapNFTListingForTest(m.live), 0, nil
		}
		return run(ctx, name, args...)
	}
	for i := range 2 {
		t.Run(itoa(i), func(t *testing.T) {
			if err := reloadNFTRules(context.Background(), env); err != nil {
				t.Fatal(err)
			}
			if m.applies != 0 {
				t.Fatal("healthy timer applied nft rules")
			}
			if _, err := containRunContainmentEvidence(probe, "987"); err != nil {
				t.Fatalf("healthy timer blocked launch evidence: %v", err)
			}
		})
	}
}

func TestReconcilePredictionFailureBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*probeEnv, *nftReloadEnv, *reconcileModel)
		fail   bool
	}{
		{"healthy", func(*probeEnv, *nftReloadEnv, *reconcileModel) {}, false},
		{"missing rules", func(_ *probeEnv, e *nftReloadEnv, m *reconcileModel) { delete(m.files, e.rulesPath) }, true},
		{"missing header", func(_ *probeEnv, e *nftReloadEnv, m *reconcileModel) { m.files[e.rulesPath] = "" }, true},
		{"corrupt header", func(_ *probeEnv, e *nftReloadEnv, m *reconcileModel) {
			m.files[e.rulesPath] = "# operator=bad pipelock-proxy=988 pipelock-agent=987"
		}, true},
		{"different port", func(p *probeEnv, _ *nftReloadEnv, _ *reconcileModel) { p.port = 9999 }, true},
		{"unreadable config", func(p *probeEnv, e *nftReloadEnv, _ *reconcileModel) {
			read := p.readFile
			p.readFile = func(path string) ([]byte, error) {
				if path == e.configPath {
					return nil, os.ErrPermission
				}
				return read(path)
			}
		}, true},
		{"missing guarded config", func(_ *probeEnv, e *nftReloadEnv, m *reconcileModel) {
			m.files[e.rulesPath] = renderNFTRulesWithServices(nftRuleOptions{OperatorUID: 1000, ProxyUID: 988, AgentUID: 987, ProxyPort: 8888, Table: defaultNFTTable, Chain: defaultNFTChain, AgentListener: "127.0.0.1:8889"})
		}, true},
		{"malformed config", func(_ *probeEnv, e *nftReloadEnv, m *reconcileModel) { m.files[e.configPath] = "containment: [" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := reconcileTestPolicy()
			env, m := newReconcileModel(nftListingFromRulesBodyForTest(policy.rules, 20))
			probe := makeProbeEnv(t, func(p *probeEnv) {
				p.nftRulesPath = env.rulesPath
				p.configPath = env.configPath
				p.readFile = env.readFile
			})
			tc.mutate(probe, env, m)
			_, _, err := predictNFTReconciliation(probe, m.live, containmentUIDs{operatorUID: 1000, operatorKnown: true, proxyUID: 988, agentUID: 987})
			if (err != nil) != tc.fail {
				t.Fatalf("prediction error=%v", err)
			}
		})
	}
}

func TestReconcileRecoveryAttemptsEveryKnownDoorway(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(fmt.Sprint(published), func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			recordPath := env.loopbackForwarderInvPath
			data := []byte(`{"services":[{"unit":"pipelock-agent-loopback-v4-9200","host":"127.0.0.1","port":9200}],"proxy_relay":true}`)
			wantAttempts := 3
			if published {
				recordPath = publishedServiceRecordPath(recordPath)
				data = []byte(`{"services":[{"unit":"pipelock-published-viewer","name":"viewer"}]}`)
				wantAttempts = 2
			}
			read := env.readFile
			env.readFile = func(path string) ([]byte, error) {
				if path == recordPath {
					return data, nil
				}
				return read(path)
			}
			env.readDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
			failure := errors.New("injected service failure")
			attempts, observations := 0, 0
			env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
				if args[0] == "show" {
					observations++
				} else {
					attempts++
				}
				return "", 1, failure
			}
			var err error
			if published {
				err = revokeKnownPublishedDoorways(context.Background(), env)
			} else {
				err = revokeKnownLoopbackDoorways(context.Background(), env)
			}
			if !errors.Is(err, failure) || !errors.Is(err, os.ErrPermission) || attempts != wantAttempts || observations != wantAttempts {
				t.Fatalf("recovery attempts=%d observations=%d error=%v", attempts, observations, err)
			}
		})
	}
}

func TestReconcileExecutorSkipsNoopAndConflict(t *testing.T) {
	for _, tc := range []struct {
		name string
		plan nftReconcilePlan
		fail bool
	}{
		{"no-op", nftReconcilePlan{}, false}, {"conflict", nftReconcilePlan{conflicts: []string{"ambiguous ownership"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated, err := executeNFTPlan(context.Background(), nftPlanExecutor{}, nftReconcilePolicy{}, tc.plan)
			if mutated || (err != nil) != tc.fail {
				t.Fatalf("executor=(%v,%v)", mutated, err)
			}
		})
	}
}

func TestReconcileFileOnlyObservationFailures(t *testing.T) {
	for _, failure := range []string{"file-observe", "file-mismatch"} {
		t.Run(failure, func(t *testing.T) {
			policy := reconcileTestPolicy()
			env, m := newReconcileModel(nftListingFromRulesBodyForTest(policy.rules, 20))
			m.files[env.rulesPath] += "# stale\n"
			m.fail = failure
			if err := reloadNFTRules(context.Background(), env); err == nil {
				t.Fatal("file-only apply reported success without observing the desired file")
			}
			if m.applies != 0 {
				t.Fatal("file-only drift applied nft rules")
			}
		})
	}
}

func TestReconcilePlansFilesAndRulesFromOneObservation(t *testing.T) {
	policy := reconcileTestPolicy()
	policy.files = []reconcileManagedFile{{"/managed/current.service", "current", modeUnitFile}, {"/managed/changed.service", "new", modeUnitFile}, {"/managed/missing.service", "new", modeUnitFile}, {"/managed/unreadable.service", "new", modeUnitFile}}
	policy.doorways = []string{"current"}
	observation := nftReconcileObservation{persisted: policy.rules, live: strings.Replace(nftListingFromRulesBodyForTest(policy.rules, 20), "tcp dport 8888", "tcp dport 8889", 1), doorways: []string{"current", "revoked"}, files: map[string]reconcileObservedFile{
		"/managed/current.service": {data: []byte("current")}, "/managed/changed.service": {data: []byte("old")}, "/managed/unreadable.service": {err: os.ErrPermission}, "/operator/foreign.service": {data: []byte("foreign")},
	}}
	plan := planNFTReconciliation(policy, observation)
	if plan.err() != nil || !plan.kernelChanged || !slices.Equal(plan.closeDoorways, []string{"revoked"}) {
		t.Fatalf("combined plan=%+v", plan)
	}
	if len(plan.writePaths) != 3 || plan.writePaths["/managed/current.service"] || plan.writePaths["/operator/foreign.service"] {
		t.Fatalf("file plan=%v", plan.writePaths)
	}
	for _, path := range []string{"/managed/changed.service", "/managed/missing.service", "/managed/unreadable.service"} {
		if !plan.writePaths[path] {
			t.Fatalf("replacement missing for %s", path)
		}
	}
	if string(observation.files["/managed/changed.service"].data) != "old" || observation.doorways[0] != "current" {
		t.Fatal("planner mutated its observation")
	}
}

func TestReconcileManagedFilePostObservation(t *testing.T) {
	files := []reconcileManagedFile{{path: "first", body: "desired"}, {path: "second", body: "desired"}}
	for _, tc := range []struct {
		name string
		data []byte
		err  error
		fail bool
	}{
		{"match", []byte("desired"), nil, false}, {"mismatch", []byte("old"), nil, true}, {"unreadable", nil, os.ErrPermission, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			err := observeManagedFilePlan(func(string) ([]byte, error) { reads++; return tc.data, tc.err }, files)
			if reads != 2 || (err != nil) != tc.fail {
				t.Fatalf("post-observation reads=%d,error=%v", reads, err)
			}
		})
	}
}

func TestReconcileDefaultDoorwayAdapterUsesListenerSnapshot(t *testing.T) {
	installed, runner, _ := newFakeEnv(t)
	env, m := newReconcileModel(nftListingFromRulesBodyForTest(reconcileTestPolicy().rules, 20))
	configureNFTReloadDoorways(env, func(io.Writer) *installEnv { return installed })
	m.files[env.configPath] = "containment:\n  agent_listener: 127.0.0.1:8889\n  loopback_services:\n    - host: 127.0.0.1\n      port: 9200\n      owner: operator\n      reason: local service\n      expires_at: '2099-01-01T00:00:00Z'\n"
	if err := reloadNFTRules(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(installed.proxyForwarderServicePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), "--target-tcp 127.0.0.1:8889") {
		t.Fatalf("snapshot target=%s", before)
	}
	m.files[env.configPath] = "containment: ["
	if err := reloadNFTRules(context.Background(), env); err == nil {
		t.Fatal("invalid listener policy reported success")
	}
	after, err := os.ReadFile(installed.proxyForwarderServicePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("invalid listener config retargeted the proxy doorway")
	}
	if !runnerCalled(runner, "stop "+loopbackForwarderUnitBase("127.0.0.1", 9200)+".service") {
		t.Fatal("invalid listener policy preserved the optional relay")
	}
}

func TestInstallNFTRulesReadsOneConfigSnapshot(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	read := env.readFile
	reads := 0
	env.readFile = func(path string) ([]byte, error) {
		if path == managedPipelockConfigPath(env) {
			reads++
			if reads > 1 {
				return []byte("containment: ["), nil
			}
			return []byte("containment:\n  agent_listener: 127.0.0.1:8889\n"), nil
		}
		return read(path)
	}
	if _, err := stepInstallNFTRules().apply(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if reads != 1 {
		t.Fatalf("managed config read %d times", reads)
	}
	data, err := os.ReadFile(env.nftRulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "tcp dport 8889") {
		t.Fatal("listener snapshot was not rendered")
	}
}

func TestReconcileInstallSerializesPromotionAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail bool
	}{
		{"success", false},
		{"rollback", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			env.reconcileLockPath = filepath.Join(filepath.Dir(env.nftRulesPath), "reconcile.lock")
			held, acquisitions, promoted, undone := false, 0, false, false
			env.lockFn = func(_ string, fn func() error) error {
				if held {
					t.Fatal("nested lock acquisition")
				}
				acquisitions++
				held = true
				defer func() { held = false }()
				return fn()
			}
			assertHeld := func() {
				t.Helper()
				if !held || !env.reconcileLockHeld {
					t.Fatal("config/doorway mutation escaped reconcile lock")
				}
			}
			steps := []step{{name: "promotion-and-doorways", apply: func(context.Context, *installEnv) (bool, error) {
				assertHeld()
				promoted = true
				return true, nil
			}, undo: func(context.Context, *installEnv) error {
				assertHeld()
				undone = true
				return nil
			}}, stepInstallNFTRules(), {name: "after-nft", apply: func(context.Context, *installEnv) (bool, error) {
				assertHeld()
				if tc.fail {
					return false, errors.New("later install failure")
				}
				return false, nil
			}}}
			err := runInstallSteps(context.Background(), env, steps)
			if (err != nil) != tc.fail || acquisitions != 1 || !promoted || undone != tc.fail || held || env.reconcileLockHeld {
				t.Fatalf("err=%v acquisitions=%d promoted=%v undone=%v held=%v env-held=%v", err, acquisitions, promoted, undone, held, env.reconcileLockHeld)
			}
		})
	}
}

func TestReconcileInstallLockFailurePrecedesMutation(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.reconcileLockPath = filepath.Join(filepath.Dir(env.nftRulesPath), "reconcile.lock")
	env.lockFn = func(string, func() error) error { return os.ErrPermission }
	called := false
	err := runInstallSteps(context.Background(), env, []step{{name: "mutation", apply: func(context.Context, *installEnv) (bool, error) {
		called = true
		return false, nil
	}}})
	if !errors.Is(err, os.ErrPermission) || called {
		t.Fatalf("err=%v mutation=%v", err, called)
	}
}

func TestReconcileInstallObservesFileOnlyApply(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	policy := reconcileTestPolicy()
	runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", policy.table, policy.chain), wrapNFTListingForTest(nftListingFromRulesBodyForTest(policy.rules, 20)), 0, nil)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.nftRulesPath, []byte(policy.rules+"# stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := env.writeFile
	env.writeFile = func(path string, data []byte, mode os.FileMode) error {
		if path == env.nftRulesPath {
			return nil // lost write while the kernel already matches
		}
		return write(path, data, mode)
	}
	if _, err := stepInstallNFTRules().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "post-apply persisted nft") {
		t.Fatalf("unobserved file-only result: %v", err)
	}
}

func TestReconcileInstallSharesPolicySnapshot(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	reads := 0
	read := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == managedPipelockConfigPath(env) {
			reads++
			if reads > 1 {
				return []byte("containment: ["), nil
			}
			return []byte("containment:\n  agent_listener: 127.0.0.1:8889\n"), nil
		}
		return read(path)
	}
	steps := []step{stepInstallNetworkNamespace(), stepInstallPublishedServices(nil), stepInstallNFTRules()}
	if err := runInstallSteps(context.Background(), env, steps); err != nil {
		t.Fatal(err)
	}
	if reads != 1 || env.policySnapshot != nil {
		t.Fatalf("policy reads=%d retained snapshot=%v", reads, env.policySnapshot != nil)
	}
}

func TestReconcileRevocationObservesRuntime(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		code        int
		err         error
		wantErr     bool
	}{
		{"inactive", "inactive", 0, nil, false},
		{"failed", "failed", 0, nil, false},
		{"active after successful stop", "active", 0, nil, true},
		{"deactivating", "deactivating", 0, nil, true},
		{"unknown", "", 1, nil, true},
		{"observation error", "", 0, os.ErrPermission, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			unit := "pipelock-published-viewer.service"
			runner.on(argvFor(testSystemctl, "show", "--property=ActiveState", "--value", unit), tc.state, tc.code, tc.err)
			if err := closePublishedDoorways(context.Background(), env, []string{unit}); (err != nil) != tc.wantErr {
				t.Fatalf("runtime observation error=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestReconcileDoorwayPredictionUsesObservedListener(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		err          error
		want         string
	}{
		{"listener", "containment:\n  agent_listener: 127.0.0.1:8889\n", nil, statusPass},
		{"unreadable", "", os.ErrPermission, statusFail},
		{"malformed", "containment: [", nil, statusFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := diagnosticDoorwayEnv(nil)
			read := env.readFile
			env.readFile = func(path string) ([]byte, error) {
				if path == env.configPath {
					return []byte(tc.config), tc.err
				}
				if path == env.proxyForwarderServicePath {
					return []byte(renderContainedProxyForwarderUnitTo(env.pipelockTarget, env.proxyUserName, "127.0.0.1:8889")), nil
				}
				return read(path)
			}
			_, result := observeManagedDoorwayDefinitions(env, nil)
			if result.status != tc.want {
				t.Fatalf("status=%s detail=%s", result.status, result.detail)
			}
		})
	}
}

func TestReconcileMissingChainPredictsReload(t *testing.T) {
	env, _ := newReconcileModel("")
	probe := makeProbeEnv(t, func(p *probeEnv) {
		p.lookupUser = containTestLookup
		p.nftRulesPath = env.rulesPath
		p.configPath = env.configPath
		p.readFile = env.readFile
		p.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return "No such file or directory", 1, nil
		}
	})
	status, detail := probeNFTContainment(context.Background(), probe)
	if status != statusFail || !strings.Contains(detail, nftReloadRemedy) {
		t.Fatalf("missing-chain prediction=%s %s", status, detail)
	}
	if result := doctorChainStructureReader(probe, &doctorEnv{port: 8888, agentUserName: defaultAgentUser})(context.Background()); result.status != statusFail || result.remediation != nftReloadRemedy {
		t.Fatalf("missing-chain doctor=%+v", result)
	}
	if err := reloadNFTRules(context.Background(), env); err != nil {
		t.Fatalf("predicted reload failed: %v", err)
	}
}

func TestReconcilePacketDiversionDoesNotMoveAheadOfDrop(t *testing.T) {
	policy := reconcileTestPolicy()
	owned := nftListingFromRulesBodyForTest(policy.rules, 20)
	drifted := strings.Replace(owned, "tcp dport 8888 accept", "tcp dport 8890 accept", 1)
	legacy := strings.Split(owned, "\n")
	for i, line := range legacy {
		fields := nftLineFields(line)
		legacy[i] = strings.Join(fields[:len(fields)-2], " ") + " # handle " + itoa(20+i)
	}
	trailingDup := "dup to 192.0.2.1 device \"eth0\" # handle 7"
	tests := []struct {
		name, live string
		conflict   bool
	}{
		{"exact owned keeps a dead trailing dup", owned + "\n" + trailingDup, false},
		{"drift must not promote a trailing dup", drifted + "\n" + trailingDup, true},
		{"dup already ahead of the drop", trailingDup + "\n" + owned, true},
		{"legacy migration must not promote a trailing dup", strings.Join(legacy, "\n") + "\n" + trailingDup, true},
		{"redirect is an implicit accept", drifted + "\nredirect to :53 # handle 7", true},
		{"dnat is an implicit accept", drifted + "\ndnat to 192.0.2.1 # handle 7", true},
		{"snat is an implicit accept", drifted + "\nsnat to 192.0.2.1 # handle 7", true},
		{"masquerade is an implicit accept", drifted + "\nmasquerade # handle 7", true},
		{"tproxy diverts to a local socket", drifted + "\ntproxy to :53 # handle 7", true},
		{"fwd diverts the packet", drifted + "\nfwd to \"eth0\" # handle 7", true},
		{"quoted dup inside a foreign drop is not a diversion", drifted + "\nmeta skuid 12345 log prefix \"dup to 192.0.2.1 \" drop # handle 7", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := planNFTReconciliation(policy, nftReconcileObservation{persisted: policy.rules, live: tc.live})
			if (plan.err() != nil) != tc.conflict {
				t.Fatalf("plan error=%v want conflict=%v script=%s", plan.err(), tc.conflict, plan.script)
			}
			if tc.conflict {
				if plan.script != "" || !strings.Contains(plan.err().Error(), "handle 7") || !strings.Contains(plan.err().Error(), "nft delete rule") {
					t.Fatalf("imprecise conflict: %+v", plan)
				}
				return
			}
			if strings.Contains(plan.script, "handle 7\n") {
				t.Fatal("foreign rule selected for deletion")
			}
			if !plan.kernelChanged {
				return
			}
			applied, err := applyNFTScriptForTest(tc.live, plan.script)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(applied, "# handle 7") {
				t.Fatalf("foreign rule dropped:\n%s", applied)
			}
			if err := checkNFTReconciliationResult(policy, plan, applied); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReconcileLiveDupConflictsAndVerifyFails(t *testing.T) {
	policy := reconcileTestPolicy()
	live := "dup to 192.0.2.1 device \"eth0\" # handle 7\n" + nftListingFromRulesBodyForTest(policy.rules, 20)
	env, m := newReconcileModel(live)
	if err := reloadNFTRules(context.Background(), env); err == nil || !strings.Contains(err.Error(), "handle 7") {
		t.Fatalf("live dup reload error=%v", err)
	}
	if m.live != live || m.applies != 0 {
		t.Fatal("conflict mutated live state")
	}
	probe := makeProbeEnv(t, func(p *probeEnv) {
		p.lookupUser = containTestLookup
		p.nftRulesPath = env.rulesPath
		p.configPath = env.configPath
		p.readFile = env.readFile
		p.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return wrapNFTListingForTest(live), 0, nil
		}
	})
	if status, detail := probeNFTContainment(context.Background(), probe); status != statusFail || !strings.Contains(detail, "handle 7") {
		t.Fatalf("verify=%s %s", status, detail)
	}
}

// The rule texts are what nft 1.1.7 prints for these verdict maps in an inet
// filter output chain. None has a bare accept token.
func TestReconcileVerdictMapIsAVerdict(t *testing.T) {
	policy := reconcileTestPolicy()
	owned := nftListingFromRulesBodyForTest(policy.rules, 20)
	drifted := strings.Replace(owned, "tcp dport 8888 accept", "tcp dport 8890 accept", 1)
	maps := map[string]string{
		"named map":        "ip daddr vmap @vm",
		"inline elements":  "meta skuid 987 tcp dport vmap { 80 : accept, 443 : continue }",
		"numgen selection": "meta skuid 987 numgen inc mod 2 vmap { 0 : accept, 1 : continue }",
		"other uid":        "meta skuid 12345 ip daddr vmap @vm",
	}
	for name, rule := range maps {
		foreign := rule + " # handle 7"
		for _, tc := range []struct {
			position, live string
		}{
			{"replacement must not promote a trailing map", drifted + "\n" + foreign},
			{"map already ahead of the drop", foreign + "\n" + owned},
		} {
			t.Run(name+"/"+tc.position, func(t *testing.T) {
				plan := planNFTReconciliation(policy, nftReconcileObservation{persisted: policy.rules, live: tc.live})
				if plan.err() == nil || plan.script != "" || !strings.Contains(plan.err().Error(), "handle 7") {
					t.Fatalf("verdict map was not a conflict: err=%v script=%s", plan.err(), plan.script)
				}
			})
		}
		t.Run(name+"/verify fails a live map", func(t *testing.T) {
			live := foreign + "\n" + owned
			env, m := newReconcileModel(live)
			if err := reloadNFTRules(context.Background(), env); err == nil || !strings.Contains(err.Error(), "handle 7") {
				t.Fatalf("reload error=%v", err)
			}
			if m.live != live || m.applies != 0 {
				t.Fatal("conflict mutated live state")
			}
			probe := makeProbeEnv(t, func(p *probeEnv) {
				p.lookupUser = containTestLookup
				p.nftRulesPath = env.rulesPath
				p.configPath = env.configPath
				p.readFile = env.readFile
				p.runCmd = func(context.Context, string, ...string) (string, int, error) {
					return wrapNFTListingForTest(live), 0, nil
				}
			})
			if status, detail := probeNFTContainment(context.Background(), probe); status != statusFail {
				t.Fatalf("verify=%s %s", status, detail)
			}
			lines := strings.Split(live, "\n")
			if !chainLinesHaveUnsafeVerdictBeforeAgentDrop(lines, containmentUIDs{operatorUID: 1000, operatorKnown: true, proxyUID: 988, agentUID: 987}, 8888) {
				t.Fatal("structural verify scanner accepted a verdict map before the agent drop")
			}
		})
	}
}

func TestReconcileForeignAcceptPreservesListenerGuard(t *testing.T) {
	for _, tc := range []struct {
		name, foreign           string
		drift, before, conflict bool
	}{
		{"replacement overlaps", "meta skuid 12345 accept", true, false, true},
		{"exact guarded state", "meta skuid 12345 accept", false, false, false},
		{"existing overlap", "meta skuid 12345 accept", false, true, true},
		{"conditional foreign port remains a conflict", "meta skuid 12345 tcp dport 8443 accept", true, false, true},
		{"conditional foreign destination remains a conflict", "meta skuid 12345 ip daddr 192.0.2.1 accept", true, false, true},
		{"conditional foreign state remains a conflict", "meta skuid 12345 ct state established accept", true, false, true},
		{"foreign drop survives", "meta skuid 12345 drop", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := reconcileTestPolicy()
			policy.rules = renderNFTRulesWithServices(nftRuleOptions{OperatorUID: 1000, ProxyUID: 988, AgentUID: 987, ProxyPort: 8888, Table: policy.table, Chain: policy.chain, AgentListener: "127.0.0.1:8889"})
			live := nftListingFromRulesBodyForTest(policy.rules, 20)
			foreign := tc.foreign + " # handle 100"
			if tc.before {
				live = foreign + "\n" + live
			} else {
				live += "\n" + foreign
			}
			if !tc.before && !chainLinesHaveAgentListenerGuard(strings.Split(live, "\n"), "127.0.0.1:8889", 988) {
				t.Fatal("positive control: original guard invalid")
			}
			if tc.drift {
				live = strings.Replace(live, "tcp dport 8888 accept", "tcp dport 8890 accept", 1)
			}
			plan := planNFTReconciliation(policy, nftReconcileObservation{persisted: policy.rules, live: live})
			if (plan.err() != nil) != tc.conflict {
				t.Fatalf("plan error=%v want conflict=%v", plan.err(), tc.conflict)
			}
			if tc.conflict {
				if plan.script != "" || !strings.Contains(plan.err().Error(), "handle 100") {
					t.Fatalf("conflict mutated or omitted handle: %+v", plan)
				}
				return
			}
			if !plan.kernelChanged {
				return
			}
			applied, err := applyNFTScriptForTest(live, plan.script)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(applied, foreign) || !chainLinesHaveAgentListenerGuard(strings.Split(applied, "\n"), "127.0.0.1:8889", 988) {
				t.Fatal("reconciliation changed the foreign rule or weakened the listener guard")
			}
		})
	}
}
