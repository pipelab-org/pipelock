// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestBridgeLifecycle_PreservesReadyBridgeFailure(t *testing.T) {
	for range 10_000 {
		bridgeErr := make(chan error, 1)
		agentDone := make(chan error, 1)
		bridgeErr <- errors.New("parent socket lost")
		agentDone <- nil

		agentErr, bridgeFailure := waitStandaloneAgentAndBridge(agentDone, bridgeErr, func() {})
		if agentErr != nil || bridgeFailure == nil {
			t.Fatalf("agent error = %v, bridge failure = %v; want nil agent error and bridge failure", agentErr, bridgeFailure)
		}
	}
}

func TestBridgeLifecycle_StopsBridgeAfterAgentExit(t *testing.T) {
	bridgeErr := make(chan error, 1)
	agentDone := make(chan error, 1)
	agentDone <- nil
	stopped := false

	agentErr, bridgeFailure := waitStandaloneAgentAndBridge(agentDone, bridgeErr, func() {
		stopped = true
		bridgeErr <- nil
	})
	if agentErr != nil || bridgeFailure != nil || !stopped {
		t.Fatalf("agent error = %v, bridge failure = %v, stopped = %t; want clean stopped bridge", agentErr, bridgeFailure, stopped)
	}
}

func TestStopTargetAfterBridgeFailureKillsWaitsThenCloses(t *testing.T) {
	for _, tc := range []struct {
		name      string
		signalErr error
	}{
		{name: "kill delivered", signalErr: nil},
		// A command that already exited still has a result to reap.
		{name: "process already done", signalErr: os.ErrProcessDone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			agentDone := make(chan error, 1)
			signal := func(sig os.Signal) error {
				if sig != os.Kill {
					t.Fatalf("signal = %v, want kill", sig)
				}
				order = append(order, "kill")
				agentDone <- errors.New("signal: killed")
				return tc.signalErr
			}
			closeTarget := func() { order = append(order, "close") }

			stopped := make(chan struct{})
			go func() {
				stopTargetAfterBridgeFailure(signal, closeTarget, agentDone)
				close(stopped)
			}()
			select {
			case <-stopped:
			case <-time.After(testwait.Deadline(5 * time.Second)):
				t.Fatal("stopTargetAfterBridgeFailure did not return: the command was not killed and reaped")
			}
			if got := strings.Join(order, ","); got != "kill,close" {
				t.Fatalf("order = %q, want kill,close", got)
			}
			select {
			case err := <-agentDone:
				t.Fatalf("agentDone was not consumed: %v", err)
			default:
			}
		})
	}
}
