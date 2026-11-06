// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"testing"
)

func TestDLPKeywordsAgentReloadResolutionError(t *testing.T) {
	previous := MergeAgentProfileFunc
	t.Cleanup(func() { MergeAgentProfileFunc = previous })
	for _, failOld := range []bool{true, false} {
		old := Defaults()
		old.Agents = map[string]AgentProfile{"operator": {}}
		next := old.Clone()
		MergeAgentProfileFunc = func(base *Config, _ *AgentProfile) (*Config, error) {
			if (base == old) == failOld {
				return nil, errors.New("profile resolution unavailable")
			}
			return base, nil
		}
		warnings := agentDLPReloadWarnings(old, next)
		if len(warnings) != 1 || warnings[0].Disposition == ReloadWarningDispositionAdvisory {
			t.Fatalf("unresolved coverage accepted: %+v", warnings)
		}
	}
}
