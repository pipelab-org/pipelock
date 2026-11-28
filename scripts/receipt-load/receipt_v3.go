// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/evidence/receiptinput"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func checkReceiptFormat(dir, expected string) error {
	claimed, err := receiptinput.Claims(dir)
	if err != nil {
		return err
	}
	if claimed != (expected == config.ReceiptFormatV3) {
		return fmt.Errorf("recorder evidence does not match --receipt-format %s", expected)
	}
	return nil
}

type v3LoadCounts struct {
	actions         int
	blockDecisions  int
	upstreamIntents int
	upstreamEnds    int
	deliveryIntents int
	deliveryEnds    int
}

func (n *v3LoadCounts) add(action v3.Action) error {
	n.actions++
	switch {
	case action.Transport != "forward" || action.Method != http.MethodGet:
		return fmt.Errorf("unexpected v3 action transport or method: %s %s", action.Transport, action.Method)
	case action.Phase == "outcome" && action.OutcomeClass != "completed":
		return fmt.Errorf("unexpected v3 %s outcome: %s", action.EffectBoundary, action.OutcomeClass)
	case action.EffectBoundary == "upstream_send" && action.Phase == "intent":
		n.upstreamIntents++
	case action.EffectBoundary == "upstream_send" && action.Phase == "outcome":
		n.upstreamEnds++
	case action.EffectBoundary == "downstream_delivery" && action.Phase == "intent":
		n.deliveryIntents++
	case action.EffectBoundary == "downstream_delivery" && action.Phase == "outcome":
		n.deliveryEnds++
	case action.Phase == "decision" && action.Verdict == "block":
		n.blockDecisions++
	}
	return nil
}

func readLoadV3(ctx context.Context, dir string, key ed25519.PublicKey, counts *v3LoadCounts) (v3.Result, error) {
	if err := checkReceiptFormat(dir, config.ReceiptFormatV3); err != nil {
		return v3.Result{}, err
	}
	ael, err := os.ReadDir(filepath.Join(dir, "ael"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return v3.Result{}, err
	}
	if len(ael) != 0 {
		return v3.Result{}, errors.New("recorder evidence contains a legacy agent event log in a v3 run")
	}
	result, err := v3.VerifyPathsWithActions(ctx, []string{dir}, v3.Options{Directory: true, Keys: []ed25519.PublicKey{key}, DiskIndex: true}, counts.add)
	if err != nil {
		return result, err
	}
	if result.Verdict != "VALID" {
		return result, fmt.Errorf("v3 verification: %s", result.Verdict)
	}
	if len(result.Legacy) != 0 {
		return result, fmt.Errorf("recorder evidence contains legacy receipts in a v3 run")
	}
	if len(result.Histories) != 1 || v3LoadTip(result.Histories[0].Streams) == nil {
		return result, errors.New("v3 load run requires one verified history with a recorded tip")
	}
	return result, nil
}

// v3IntegrityRun is what a finished v3 load run hands to the integrity check.
type v3IntegrityRun struct {
	opt      options
	dirs     runDirs
	plan     workload
	sink     *sink
	outcomes []requestOutcome
	shutdown shutdownReport
}

func finishV3Integrity(ctx context.Context, run v3IntegrityRun) integrityReport {
	opt, dirs, plan, sink, outcomes, shutdown := run.opt, run.dirs, run.plan, run.sink, run.outcomes, run.shutdown
	rep := integrityReport{
		Verdict: verdictPass, Kinds: make(map[string]kindReport), Reasons: []string{},
		ReceiptAttribution: "aggregate", Shutdown: shutdown,
	}
	if !shutdown.Clean {
		rep.fail("shutdown: " + shutdown.Error)
	}
	var blocked int
	for slot, hits := range sink.hits() {
		b := plan.blocked(slot)
		validResponse := false
		if slot < len(outcomes) {
			validResponse = outcomes[slot].expectedResponse()
		}
		if !validResponse {
			rep.fail(fmt.Sprintf("%s: request did not complete with the expected response", plan.key(slot)))
		}
		accountSink(&rep.Sink, b, hits, plan.key(slot))
		if b {
			blocked++
		}
	}
	rep.Sink.Orphan += int(sink.unknown.Load())
	rep.Sink.finish(false)
	if rep.Sink.Status != statusOK {
		rep.fail(describeKind("sink", rep.Sink))
	}

	verifyCtx, cancel := context.WithTimeout(ctx, verificationTimeout(opt))
	defer cancel()
	var counts v3LoadCounts
	var result v3.Result
	rep.Verify, result = verifyLoadV3(verifyCtx, dirs, &counts)
	if rep.Verify.Exit != 0 {
		rep.fail(rep.Verify.Output)
		return rep
	}
	if opt.restartAfter > 0 && !v3LoadContinues(result.Histories[0].Streams, opt.restartV3) {
		rep.fail("restart continuity: verified history does not extend the pre-restart tip")
	}
	allowed := plan.total() - blocked
	for _, row := range []struct {
		name string
		want int
		got  int
	}{
		{"v3_upstream_intent", allowed, counts.upstreamIntents},
		{"v3_upstream_outcome", allowed, counts.upstreamEnds},
		{"v3_delivery_intent", allowed, counts.deliveryIntents},
		{"v3_delivery_outcome", allowed, counts.deliveryEnds},
		{"v3_block_decision", blocked, counts.blockDecisions},
	} {
		var kind kindReport
		accountSlot(&kind, row.want, row.got, "workload")
		kind.finish(false)
		rep.Kinds[row.name] = kind
		rep.ReceiptMissing += kind.Missing
		if kind.Status != statusOK {
			rep.fail(describeKind(row.name, kind))
		}
	}
	if counts.actions != counts.upstreamIntents+counts.upstreamEnds+counts.deliveryIntents+counts.deliveryEnds+counts.blockDecisions {
		rep.fail(fmt.Sprintf("v3 action count includes %d unexpected records", counts.actions-counts.upstreamIntents-counts.upstreamEnds-counts.deliveryIntents-counts.deliveryEnds-counts.blockDecisions))
	}
	return rep
}

// The verification document orders streams by ID. Use its authenticated
// predecessor links to find the tip, independently of presentation order.
func v3LoadTip(streams []v3.StreamResult) *v3.StreamResult {
	predecessors := make(map[string]bool, len(streams))
	for _, stream := range streams {
		predecessors[stream.Previous] = true
	}
	for i := range streams {
		if !predecessors[streams[i].Stream] && streams[i].Last != nil {
			return &streams[i]
		}
	}
	return nil
}

func v3LoadContinues(streams []v3.StreamResult, tip *v3.StreamResult) bool {
	if tip == nil || tip.Last == nil {
		return false
	}
	var retained, extended bool
	for _, stream := range streams {
		retained = retained || stream.Stream == tip.Stream && stream.Last != nil && *stream.Last == *tip.Last
		extended = extended || stream.Previous == tip.Stream
	}
	return retained && extended
}

func verifyLoadV3(ctx context.Context, dirs runDirs, counts *v3LoadCounts) (verifyReport, v3.Result) {
	rep := verifyReport{Ran: true}
	key, err := signing.LoadPublicKey(filepath.Join(dirs.keys, "flight-recorder-signing.key.pub"))
	var result v3.Result
	if err == nil {
		result, err = readLoadV3(ctx, dirs.recorder, key, counts)
		if result.Verdict != "" {
			data, marshalErr := json.Marshal(result)
			if marshalErr != nil {
				err = errors.Join(err, marshalErr)
			}
			rep.Output = string(data) + "\n"
		}
	}
	if err != nil {
		rep.Exit = -1
		rep.Output += err.Error()
	}
	if err := os.WriteFile(filepath.Join(dirs.root, "verify.txt"), []byte(rep.Output), 0o600); err != nil {
		rep.Exit = -1
		rep.Output += "\nwriting verify.txt: " + err.Error()
	}
	return rep, result
}
