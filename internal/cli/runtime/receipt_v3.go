// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	wireReceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/posturebinding"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func receiptV3Selected(cfg *config.Config) (bool, error) {
	fr := cfg.FlightRecorder
	switched, err := v3.DirectoryHasV3(fr.Dir)
	if err != nil {
		return false, err
	}
	if switched && fr.ReceiptFormat == config.ReceiptFormatLegacy {
		return false, errors.New("flight_recorder.receipt_format legacy requires a new evidence directory after a v3 switch")
	}
	if !switched && fr.ReceiptFormat != config.ReceiptFormatV3 {
		return false, nil
	}
	if err := cfg.ValidateReceiptV3(); err != nil {
		return false, err
	}
	return true, nil
}

func refuseUnwiredReceiptV3(cfg *config.Config) error {
	useV3, err := receiptV3Selected(cfg)
	if err != nil {
		return err
	}
	if useV3 {
		return errors.New("flight_recorder.receipt_format v3 is unavailable in this runtime")
	}
	return nil
}

const receiptOperationalDirectory = "operational"

type runtimeReceiptStreamOptions struct {
	surfaces         []string
	onHeartbeatError func(error)
}

type runtimeReceiptV3Opener func(context.Context, *config.Config, ed25519.PrivateKey, *recorder.Recorder, posturebinding.Result, runtimeReceiptStreamOptions) (*v3.StreamWriter, error)

func openRuntimeReceiptV3(ctx context.Context, cfg *config.Config, key ed25519.PrivateKey, rec *recorder.Recorder, posture posturebinding.Result, opts runtimeReceiptStreamOptions) (*v3.StreamWriter, error) {
	fr := cfg.FlightRecorder
	keys := make([]ed25519.PublicKey, 0, len(fr.ReceiptGroupPriorSignerKeys))
	for _, encoded := range fr.ReceiptGroupPriorSignerKeys {
		keyBytes, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode prior receipt signer key: %w", err)
		}
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, errors.New("prior receipt signer key must be an Ed25519 public key")
		}
		keys = append(keys, ed25519.PublicKey(keyBytes))
	}
	var binding *v3.Posture
	if posture.HasContainmentAttestation() {
		binding = &v3.Posture{
			CapsuleSHA256: "sha256:" + strings.TrimPrefix(posture.Binding.CapsuleSHA256, "sha256:"),
			SignerKeyID:   posture.Binding.SignerKeyID, ContainedUID: posture.Binding.ContainedUID,
			ContainmentNonce: posture.Binding.ContainmentNonce,
		}
	}
	rules := wireReceipt.DefaultCanonicalizationProfile()
	return v3.OpenStreamWriter(ctx, v3.StreamWriterOptions{
		Dir: fr.Dir, SigningKey: key, PriorSignerKeys: keys,
		Identity:   v3.Writer{Instance: receipt.NewActionID(), Product: "Pipelock", Version: cliutil.Version},
		PolicyHash: "sha256:" + strings.TrimPrefix(cfg.CanonicalPolicyHash(), "sha256:"),
		Posture:    binding, RecorderSession: rec.SessionID(), Detector: rec.ReceiptDetector(),
		Heartbeat:        time.Duration(fr.HeartbeatIntervalSecondsForReceipt()) * time.Second,
		OnHeartbeatError: opts.onHeartbeatError,
		Coverage: v3.Coverage{
			ReceiptsRequired: fr.RequireReceipts, ContentScan: fr.Redact, Surfaces: opts.surfaces,
			RedactionRuleset: v3.Ruleset{ID: rules.RedactionRulesetID, Version: rules.RedactionRulesetVersion, Hash: rules.RedactionRulesetHash},
		},
	})
}

func serverReceiptSurfaces(cfg *config.Config, hasMCPListener, reverseFlag bool) []string {
	surfaces := []string{"fetch"}
	if cfg.ForwardProxy.Enabled {
		surfaces = append(surfaces, "connect", "forward")
		if cfg.TLSInterception.Enabled {
			surfaces = append(surfaces, "intercept")
		}
	}
	if cfg.WebSocketProxy.Enabled {
		surfaces = append(surfaces, "websocket")
	}
	if cfg.ReverseProxy.Enabled || reverseFlag {
		surfaces = append(surfaces, "reverse")
	}
	if hasMCPListener {
		surfaces = append(surfaces, deferred.SurfaceMCPHTTPListener)
	}
	return surfaces
}

func checkReceiptFormatReload(old, next config.FlightRecorder, liveV3 bool) error {
	liveFormat := config.ReceiptFormatLegacy
	if liveV3 {
		liveFormat = config.ReceiptFormatV3
	}
	format := next.ReceiptFormat
	if format == "" {
		format = liveFormat
		if next.Dir != old.Dir {
			switched, err := v3.DirectoryHasV3(next.Dir)
			if err != nil {
				return err
			}
			format = config.ReceiptFormatLegacy
			if switched {
				format = config.ReceiptFormatV3
			}
		}
	}
	if format != liveFormat {
		return errors.New("flight_recorder.receipt_format changed; restart required")
	}
	return nil
}

func checkV3ReloadCoverage(oldCfg, newCfg *config.Config, hasMCPListener, reverseFlag bool) error {
	oldFR, newFR := oldCfg.FlightRecorder, newCfg.FlightRecorder
	switch {
	case oldFR.RequireReceipts != newFR.RequireReceipts:
		return errors.New("flight_recorder.require_receipts changed; restart required")
	case oldFR.Redact != newFR.Redact:
		return errors.New("flight_recorder.redact changed; restart required")
	case oldFR.RequireContainmentEvidence != newFR.RequireContainmentEvidence ||
		oldFR.PostureSignerKey != newFR.PostureSignerKey:
		return errors.New("flight_recorder containment posture changed; restart required")
	case !slices.Equal(serverReceiptSurfaces(oldCfg, hasMCPListener, reverseFlag), serverReceiptSurfaces(newCfg, hasMCPListener, reverseFlag)):
		return errors.New("receipt coverage surfaces changed; restart required")
	default:
		return nil
	}
}

func finishReceiptV3(ctx context.Context, writer *v3.StreamWriter, incomplete bool) error {
	if incomplete {
		return writer.CloseUnsealed(ctx)
	}
	return writer.Close(ctx, nil)
}
