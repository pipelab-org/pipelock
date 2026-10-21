// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

// emitActivationAuditMethod labels the audit record written when a configured
// emit sink fails to activate.
const emitActivationAuditMethod = "EMIT_ACTIVATION"

// startAuditEmitter builds the sinks configured under emit, activates them,
// and attaches the resulting emitter to logger. pipelock run and pipelock mcp
// proxy share it so a configured audit destination means the same thing on
// both. If any sink fails to activate, every sink is closed and an error is
// returned: the caller must abort startup rather than run with configured
// audit delivery silently missing. The returned sinks are the activated set,
// which the run server keeps for reload bookkeeping.
func startAuditEmitter(cfg *config.Config, logger *audit.Logger, m *metrics.Metrics, configFile string, stderr io.Writer) (*emit.Emitter, []emit.Sink, error) {
	sinks, err := BuildEmitSinks(cfg, m)
	if err != nil {
		return nil, nil, fmt.Errorf("creating emit sinks: %w", err)
	}
	instanceID := cfg.Emit.InstanceID
	if instanceID == "" {
		instanceID = emit.DefaultInstanceID()
	}
	if activationErr := activateEmitSinks(sinks); activationErr != nil {
		activationErr = fmt.Errorf("activating configured emit sinks: %w", activationErr)
		logger.LogError(audit.NewResourceLogContext(emitActivationAuditMethod, configFile), activationErr)
		_, _ = fmt.Fprintf(stderr, "WARNING: audit sink activation failed; startup aborted so configured audit delivery cannot be bypassed: %v\n", activationErr)
		for _, sink := range sinks {
			_ = sink.Close()
		}
		return nil, nil, activationErr
	}
	emitter := emit.NewEmitter(instanceID, sinks...)
	m.SetAuditSinkHealthSnapshot(emitter.SinkHealth)
	logger.SetEmitter(emitter)
	return emitter, sinks, nil
}
