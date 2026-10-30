// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
	"os/exec"
	"runtime"
	"sync"
)

type targetSignal struct {
	signal os.Signal
	result chan error
}

// sandboxTarget keeps launch and signal delivery in the same Landlock domain.
// Before ABI 8, restricting every Go thread creates distinct domains even when
// their rules match. A child inherits its spawning thread's domain; another
// thread may therefore be forbidden from signaling it.
type sandboxTarget struct {
	signals chan targetSignal
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
}

// startSandboxTarget reserves a thread for the target's lifetime. The caller
// must Close it after Wait, including error paths. Close retires the thread;
// it does not kill or reap the target.
func startSandboxTarget(cmd *exec.Cmd, filesystem LayerStatus) (*sandboxTarget, error) {
	target := &sandboxTarget{
		signals: make(chan targetSignal),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if cmd.Cancel != nil {
		// CommandContext's watcher runs on a different Go thread. Route its
		// cancellation through the spawning thread just like explicit signals.
		cmd.Cancel = func() error { return target.Signal(os.Kill) }
	}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// No UnlockOSThread: the workload-only seccomp filter is permanent,
		// so this thread must never return to the bridge's worker pool.
		defer close(target.done)
		if err := restrictSandboxTarget(filesystem); err != nil {
			started <- err
			return
		}
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		for {
			select {
			case request := <-target.signals:
				request.result <- cmd.Process.Signal(request.signal)
			case <-target.stop:
				return
			}
		}
	}()
	if err := <-started; err != nil {
		<-target.done
		return nil, err
	}
	return target, nil
}

func (t *sandboxTarget) Signal(signal os.Signal) error {
	request := targetSignal{signal: signal, result: make(chan error, 1)}
	select {
	case t.signals <- request:
		return <-request.result
	case <-t.done:
		return os.ErrProcessDone
	}
}

func (t *sandboxTarget) Close() {
	t.once.Do(func() { close(t.stop) })
	<-t.done
}
