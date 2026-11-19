// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"errors"
	"time"
)

func (w *StreamWriter) startHeartbeats(interval time.Duration, onError func(error)) {
	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	w.stopHeartbeat = func() {
		cancel()
		<-done
	}
	go func() {
		defer close(done)
		defer ticker.Stop()
		w.runHeartbeats(ctx, ticker.C, onError)
	}()
}

func (w *StreamWriter) runHeartbeats(ctx context.Context, ticks <-chan time.Time, onError func(error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			err := w.WriteHeartbeat(ctx)
			if err != nil && onError != nil && !errors.Is(err, context.Canceled) {
				onError(err)
			}
		}
	}
}
