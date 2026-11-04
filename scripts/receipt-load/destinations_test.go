// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDestinationPlan(t *testing.T) {
	for _, total := range []int{1, 2, 3, 4, 5, 50, 20000, 1001000} {
		t.Run(fmt.Sprint(total), func(t *testing.T) {
			ports := make([]string, destinationPoolSize(total))
			for i := range ports {
				ports[i] = fmt.Sprint(10000 + i)
			}
			d := newDestinationPlan(total, ports)
			for slot := range total {
				target := "http://" + d.authority(slot)
				got, ok := d.targetSlot(target, total)
				if !ok || got != slot {
					t.Fatalf("slot %d: %d %v", slot, got, ok)
				}
			}
			if len(d.Aliases)*len(d.Ports) < total {
				t.Fatal("pool does not cover plan")
			}
			target := "http://" + d.authority(0)
			for _, bad := range []string{"garbage", "http://", target + "/", target + "?", target + "#", target + "?wk=s1-m000000", strings.Replace(target, "http:", "https:", 1), strings.Replace(target, "r000000", "R000000", 1), "http://unknown.load.example:" + ports[0], "http://r000000.load.example:1", "[redacted-target]"} {
				if _, ok := d.targetSlot(bad, total); ok {
					t.Fatalf("accepted %q", bad)
				}
			}
			if total%len(ports) != 0 {
				unused := net.JoinHostPort(d.Aliases[len(d.Aliases)-1], ports[len(ports)-1])
				if _, ok := d.targetSlot("http://"+unused, total); ok {
					t.Fatal("unused pair accepted")
				}
			}
		})
	}
}

func TestPerRequestRealProducer(t *testing.T) {
	binary := realPipelock(t)
	for _, chains := range []int{1, 2} {
		for _, mode := range []string{modeOff, modeBest, modeRequired} {
			t.Run(fmt.Sprintf("%s/%d", mode, chains), func(t *testing.T) {
				opt := smallOptions(t, binary)
				opt.chains, opt.destinations = chains, destinationsPerRequest
				res, err := runMode(context.Background(), opt, mode)
				wantAttribution := attributionPerRequestDestination
				if mode == modeOff {
					wantAttribution = ""
				}
				if err != nil || res.Integrity.Verdict != verdictPass || res.Performance.Verdict != perfMeasured || res.Integrity.ReceiptAttribution != wantAttribution {
					t.Fatalf("producer: %v %+v", err, res)
				}
				if res.Inputs.Harness.ContractVersion != "7" || res.Inputs.Workload.Destinations != destinationsPerRequest {
					t.Fatalf("contract: %+v", res.Inputs)
				}
				var cfg struct {
					DNS struct {
						Overrides map[string][]string `yaml:"host_overrides"`
					} `yaml:"dns"`
					SSRF struct {
						Allowlist []string `yaml:"ip_allowlist"`
					} `yaml:"ssrf"`
				}
				if err := yaml.Unmarshal([]byte(res.Inputs.Config.YAML), &cfg); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(cfg.SSRF.Allowlist, []string{"127.0.0.1/32"}) || !reflect.DeepEqual(cfg.DNS.Overrides, res.Inputs.Workload.DestinationPool.overrides()) {
					t.Fatalf("config changed trust or lost aliases: %+v", cfg)
				}
				dir := mode
				if chains > 1 {
					dir = fmt.Sprintf("chains-%d-%s", chains, mode)
				}
				check, err := os.ReadFile(filepath.Clean(filepath.Join(opt.out, dir, "check.txt")))
				if err != nil || len(check) == 0 {
					t.Fatalf("real config check: %q %v", check, err)
				}
				t.Logf("%s chains=%d: integrity=%s attribution=%s ports=%d aliases=%d", mode, chains, res.Integrity.Verdict, res.Integrity.ReceiptAttribution, len(res.Inputs.Workload.DestinationPool.Ports), len(res.Inputs.Workload.DestinationPool.Aliases))
			})
		}
	}
}

// Preserve stream totals while moving observations from one allowed request
// to another in the same shard. These are accounting mutations, not a claim
// that edited signatures verify; the unmodified producer is verified first.
func TestPerRequestCompensatedLoss(t *testing.T) {
	for _, mode := range []string{modeRequired, modeBest} {
		t.Run(mode, func(t *testing.T) {
			opt := smallOptions(t, realPipelock(t))
			opt.requests, opt.warmup, opt.destinations = 4, 0, destinationsPerRequest
			res, err := runMode(context.Background(), opt, mode)
			if err != nil || res.Integrity.Verdict != verdictPass {
				t.Fatalf("producer control: %v %+v", err, res)
			}
			plan := newWorkload(opt.seed, 0, opt.requests)
			plan.runNonce = strings.TrimPrefix(res.Inputs.Workload.Tag, plan.tag()+"-r")
			plan.destinations = res.Inputs.Workload.DestinationPool
			dirs := newRunDirs(filepath.Join(opt.out, mode))
			paths, err := filepath.Glob(filepath.Join(dirs.recorder, "evidence-*.jsonl"))
			if err != nil || len(paths) != 1 {
				t.Fatalf("same-shard precondition: %v %v", paths, err)
			}
			raw, err := os.ReadFile(paths[0])
			if err != nil {
				t.Fatal(err)
			}
			control, err := scanRecorder(dirs.recorder, plan, "")
			if err != nil {
				t.Fatal(err)
			}
			in := integrityInput{mode: mode, plan: plan, obs: control, outcomes: make([]requestOutcome, plan.total()), sinkHits: make([]int, plan.total())}
			for slot := range plan.total() {
				if plan.blocked(slot) {
					t.Fatal("fixture requires allowed requests")
				}
				in.sinkHits[slot] = 1
				in.outcomes[slot] = requestOutcome{ran: true, receiptHeader: control.slots[slot].actionIDs[0]}
			}
			if got := evaluateIntegrity(in); got.Verdict != verdictPass {
				t.Fatalf("identity control: %+v", got)
			}
			from, to := "http://"+plan.destinations.authority(0), "http://"+plan.destinations.authority(1)
			victimID := control.slots[0].actionIDs[0]
			freshID := "compensated-fresh-action"
			moved := 0
			lines := strings.Split(string(raw), "\n")
			for i, line := range lines {
				var env evidenceEnvelope
				if json.Unmarshal([]byte(line), &env) != nil {
					continue
				}
				if !strings.Contains(line, from) || (mode == modeRequired && env.Type != recordTypeEvidence) {
					continue
				}
				var rec map[string]any
				if err := json.Unmarshal([]byte(line), &rec); err != nil {
					t.Fatal(err)
				}
				detail := rec["detail"].(map[string]any)
				switch env.Type {
				case recordTypeEvidence:
					detail["event_id"] = fmt.Sprintf("fresh-v2-%d", i)
					detail["payload"].(map[string]any)["target"] = to
				case recordTypeAction:
					ar := detail["action_record"].(map[string]any)
					ar["target"], ar["action_id"] = to, freshID
				default:
					continue
				}
				data, err := json.Marshal(rec)
				if err != nil {
					t.Fatal(err)
				}
				lines[i] = string(data)
				moved++
			}
			if moved != 2 {
				t.Fatalf("moved %d observations, want 2", moved)
			}
			writeReviewFile(t, paths[0], strings.Join(lines, "\n"))
			if mode == modeBest {
				aelPaths, err := filepath.Glob(filepath.Join(dirs.recorder, "ael", "*", "recorders", "pipelock.jsonl"))
				if err != nil || len(aelPaths) != 1 {
					t.Fatalf("AEL paths: %v %v", aelPaths, err)
				}
				data, err := os.ReadFile(aelPaths[0])
				if err != nil {
					t.Fatal(err)
				}
				activities := strings.Split(string(data), "\n")
				changed := 0
				for i, line := range activities {
					payload, sig, ok := strings.Cut(line, ".")
					if !ok {
						continue
					}
					decoded, err := base64.RawURLEncoding.DecodeString(payload)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(decoded), victimID) {
						decoded = []byte(strings.ReplaceAll(string(decoded), victimID, freshID))
						activities[i] = base64.RawURLEncoding.EncodeToString(decoded) + "." + sig
						changed++
					}
				}
				if changed != 1 {
					t.Fatalf("moved %d AEL activities", changed)
				}
				writeReviewFile(t, aelPaths[0], strings.Join(activities, "\n"))
			}
			mutated, err := scanRecorder(dirs.recorder, plan, "")
			if err != nil {
				t.Fatal(err)
			}
			in.obs = mutated
			got := evaluateIntegrity(in)
			if got.Verdict != verdictFail || got.Kinds["v2"].Missing != int(expectedFor(mode, false)[kindV2]) || got.Kinds["v2"].Duplicate != int(expectedFor(mode, false)[kindV2]) {
				t.Fatalf("compensated loss passed identity guard: %+v", got)
			}
			for _, kind := range []string{"v1_allow", "v1_intent", "v1_outcome", "v2", "ael"} {
				k := got.Kinds[kind]
				if k.Expected != k.Observed {
					t.Fatalf("totals changed for %s: %+v", kind, k)
				}
			}
			t.Logf("totals preserved; identity rejected %s: %v", mode, got.Reasons)
		})
	}
}
