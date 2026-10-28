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
	// Both results are ready, so select takes either one first. Each iteration
	// runs the same cleanup RunStandaloneInit runs, which must finish whichever
	// side the wait consumed.
	sawReaped, sawUnreaped := false, false
	for range 10_000 {
		bridgeErr := make(chan error, 1)
		agentDone := make(chan error, 1)
		bridgeErr <- errors.New("parent socket lost")
		agentDone <- nil

		agentErr, bridgeFailure, reaped := waitStandaloneAgentAndBridge(agentDone, bridgeErr, func() {})
		if agentErr != nil || bridgeFailure == nil {
			t.Fatalf("agent error = %v, bridge failure = %v; want nil agent error and bridge failure", agentErr, bridgeFailure)
		}
		if reaped {
			sawReaped = true
		} else {
			sawUnreaped = true
		}
		runBridgeFailureCleanup(t, reaped, agentDone)
	}
	if !sawReaped || !sawUnreaped {
		t.Fatalf("reaped orderings seen: reaped=%t unreaped=%t; want both", sawReaped, sawUnreaped)
	}
}

func TestBridgeLifecycle_AgentFirstThenBridgeFailureCleansUp(t *testing.T) {
	bridgeErr := make(chan error, 1)
	agentDone := make(chan error, 1)
	agentDone <- errKilledForTest

	agentErr, bridgeFailure, reaped := waitStandaloneAgentAndBridge(agentDone, bridgeErr, func() {
		bridgeErr <- errors.New("parent socket lost")
	})
	if !errors.Is(agentErr, errKilledForTest) || bridgeFailure == nil || !reaped {
		t.Fatalf("agent error = %v, bridge failure = %v, reaped = %t; want agent result, bridge failure, reaped", agentErr, bridgeFailure, reaped)
	}
	runBridgeFailureCleanup(t, reaped, agentDone)
}

// runBridgeFailureCleanup runs stopTargetAfterBridgeFailure the way
// RunStandaloneInit does. Its signal stub only produces a Wait result while one
// is still owed: a reaped command has none, as in the real process.
func runBridgeFailureCleanup(t *testing.T, reaped bool, agentDone chan error) {
	t.Helper()
	killed, closed := false, false
	signal := func(os.Signal) error {
		killed = true
		if len(agentDone) == 0 && !reaped {
			agentDone <- errKilledForTest
		}
		return os.ErrProcessDone
	}
	stopped := make(chan struct{})
	go func() {
		_ = stopTargetAfterBridgeFailure(reaped, signal, func() { closed = true }, agentDone)
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatalf("cleanup hung (reaped=%t): it waited for an agent result already consumed", reaped)
	}
	if !closed {
		t.Fatal("target was not closed")
	}
	if killed == reaped {
		t.Fatalf("killed = %t with reaped = %t; want a kill only for a command not yet reaped", killed, reaped)
	}
	if len(agentDone) != 0 {
		t.Fatal("agentDone result was left unconsumed")
	}
}

func TestBridgeLifecycle_StopsBridgeAfterAgentExit(t *testing.T) {
	bridgeErr := make(chan error, 1)
	agentDone := make(chan error, 1)
	agentDone <- nil
	stopped := false

	agentErr, bridgeFailure, reaped := waitStandaloneAgentAndBridge(agentDone, bridgeErr, func() {
		stopped = true
		bridgeErr <- nil
	})
	if agentErr != nil || bridgeFailure != nil || !stopped || !reaped {
		t.Fatalf("agent error = %v, bridge failure = %v, stopped = %t, reaped = %t; want clean stopped bridge after reaping", agentErr, bridgeFailure, stopped, reaped)
	}
}

var errKilledForTest = errors.New("signal: killed")

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
				agentDone <- errKilledForTest
				return tc.signalErr
			}
			closeTarget := func() { order = append(order, "close") }

			stopped := make(chan error, 1)
			go func() {
				stopped <- stopTargetAfterBridgeFailure(false, signal, closeTarget, agentDone)
			}()
			select {
			case err := <-stopped:
				if !errors.Is(err, errKilledForTest) || errors.Is(err, errSandboxKillFailed) {
					t.Fatalf("reaped result = %v, want the Wait goroutine's error and no failed-kill report", err)
				}
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

func TestStopTargetAfterBridgeFailureDoesNotWaitWhenKillFails(t *testing.T) {
	errKillRefused := errors.New("operation not permitted")
	agentDone := make(chan error, 1) // never receives: the command was not killed
	closed := false
	signal := func(os.Signal) error { return errKillRefused }

	stopped := make(chan error, 1)
	go func() {
		stopped <- stopTargetAfterBridgeFailure(false, signal, func() { closed = true }, agentDone)
	}()
	select {
	case err := <-stopped:
		if !errors.Is(err, errKillRefused) || !errors.Is(err, errSandboxKillFailed) {
			t.Fatalf("result = %v, want the kill error marked as a failed kill", err)
		}
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("cleanup waited for a command it could not kill")
	}
	if !closed {
		t.Fatal("target was not closed")
	}
}
