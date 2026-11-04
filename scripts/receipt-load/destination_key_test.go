// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAggregateDestinationShape(t *testing.T) {
	scanner := &recorderScanner{sinkAddr: synthSink}
	target := "http://" + synthSink
	if scanner.classify(target) != targetAggregate {
		t.Fatal("positive destination rejected")
	}
	for _, bad := range []string{target + "/", target + "?", target + "#", target + "#request", "https://" + synthSink, "http://user@" + synthSink, "http://127.0.0.2:9"} {
		if scanner.classify(bad) == targetAggregate {
			t.Fatalf("unplanned shape accepted: %q", bad)
		}
	}
}

// Use sealed production output, then change only the receipt stream. Neither
// a sound response nor a preserved destination may conceal evidence damage.
func TestDestinationReceiptsRejectMissingAndTampered(t *testing.T) {
	opt := smallOptions(t, realPipelock(t))
	opt.requests, opt.warmup = 4, 0
	res, err := runMode(context.Background(), opt, modeRequired)
	if err != nil || res.Integrity.Verdict != verdictPass {
		t.Fatalf("real producer control: %v %+v", err, res)
	}
	dirs := newRunDirs(filepath.Join(opt.out, modeRequired))
	plan := newWorkload(opt.seed, opt.warmup, opt.requests)
	plan.runNonce = strings.TrimPrefix(res.Inputs.Workload.Tag, plan.tag()+"-r")
	paths, err := filepath.Glob(filepath.Join(dirs.recorder, "evidence-*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("recorder paths: %v %v", paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	obs, err := scanRecorder(dirs.recorder, plan, extractSinkHost(t, string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := buildChildEnv(os.Environ(), dirs)
	for _, mutation := range []string{"missing", "tampered"} {
		t.Run(mutation, func(t *testing.T) {
			defer func() {
				if err := os.WriteFile(paths[0], raw, 0o600); err != nil {
					t.Error(err)
				}
			}()
			lines := strings.Split(string(raw), "\n")
			changed := false
			for i, line := range lines {
				var record evidenceEnvelope
				if json.Unmarshal([]byte(line), &record) != nil || record.Type != recordTypeAction || !strings.Contains(line, `"target":"http://`) {
					continue
				}
				if mutation == "missing" {
					lines = append(lines[:i], lines[i+1:]...)
				} else {
					lines[i] = strings.Replace(line, "http://"+extractSinkHost(t, string(raw)), "http://127.0.0.2:9", 1)
				}
				changed = true
				break
			}
			if !changed {
				t.Fatal("mutation matched no production receipt")
			}
			if err := os.WriteFile(paths[0], []byte(strings.Join(lines, "\n")), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if got := verifyRecorder(ctx, filepath.Join(dirs.root, "bin", "pipelock"), dirs, env, obs); got.Exit == 0 {
				t.Fatalf("%s receipt accepted: %+v", mutation, got)
			} else {
				t.Logf("%s rejected: exit %d, %s", mutation, got.Exit, got.Output)
			}
		})
	}
}
