// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/extract"
)

// The config ceiling must be the field tail ceiling: a larger config value
// would validate and then be silently clamped at runtime.
func TestWebSocketCrossMessageFieldLimitMatchesFieldTailCeiling(t *testing.T) {
	if MaxWebSocketCrossMessageFieldLimit != extract.FieldTailMaxPathsLimit {
		t.Fatalf("config max %d != extract max %d", MaxWebSocketCrossMessageFieldLimit, extract.FieldTailMaxPathsLimit)
	}
	if DefaultWebSocketCrossMessageFieldLimit > MaxWebSocketCrossMessageFieldLimit {
		t.Fatal("default exceeds max")
	}
}

func TestWebSocketCrossMessageFieldLimitValidation(t *testing.T) {
	for _, tc := range []struct {
		limit int
		ok    bool
	}{
		{0, true},
		{16, true},
		{MaxWebSocketCrossMessageFieldLimit, true},
		{-1, false},
		{MaxWebSocketCrossMessageFieldLimit + 1, false},
	} {
		cfg := Defaults()
		cfg.WebSocketProxy.Enabled = true
		cfg.WebSocketProxy.CrossMessageFieldLimit = tc.limit
		err := cfg.Validate()
		if tc.ok && err != nil {
			t.Errorf("limit %d: unexpected error %v", tc.limit, err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "cross_message_field_limit")) {
			t.Errorf("limit %d: err = %v, want cross_message_field_limit error", tc.limit, err)
		}
	}
}
