// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

func receiptV3Selected(cfg config.FlightRecorder) (bool, error) {
	switched, err := v3.DirectoryHasV3(cfg.Dir)
	if err != nil {
		return false, err
	}
	if switched && cfg.ReceiptFormat == config.ReceiptFormatLegacy {
		return false, errors.New("flight_recorder.receipt_format legacy requires a new evidence directory after a v3 switch")
	}
	if !switched && cfg.ReceiptFormat != config.ReceiptFormatV3 {
		return false, nil
	}
	if cfg.ReceiptChainCount() > 1 {
		return false, errors.New("flight_recorder.receipt_format v3 requires at most one flight_recorder.receipt_chains chain")
	}
	if !cfg.Enabled || cfg.SigningKeyPath == "" {
		return false, errors.New("flight_recorder.receipt_format v3 requires flight_recorder.enabled and signing_key_path")
	}
	return true, nil
}

func refuseUnwiredReceiptV3(cfg config.FlightRecorder) error {
	useV3, err := receiptV3Selected(cfg)
	if err != nil {
		return err
	}
	if useV3 {
		return errors.New("flight_recorder.receipt_format v3 is unavailable in this runtime")
	}
	return nil
}
