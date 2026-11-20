// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/activation"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	contractstore "github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/directorysync"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	defaultLifecycleReceiptOut = "activation-receipts.jsonl"
	genesisManifestHash        = "sha256:genesis"
	emptyHistoryRootHash       = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	lifecycleOutcomeAccepted   = "accepted"
	lifecycleOutcomeRejected   = "rejected"
)

type lifecycleFlags struct {
	storeDir              string
	rosterPath            string
	rosterRootFingerprint string
	keystore              string
	activationKey         string
	dualControlFrom       string
	receiptKey            string
	receiptOut            string
	environmentID         string
	tenant                string
	deploymentID          string
	production            bool
	deterministic         bool
	contractHash          string
	selector              string
	rollbackTarget        string
	intentID              string
	authorizationID       string
	receiptSync           lifecycleReceiptSync
}

type lifecycleContext struct {
	store         contractstore.Store
	opts          contractstore.Options
	roster        *signing.LoadedRoster
	now           time.Time
	policy        activation.Policy
	activationKey privateKeySigner
	dualKey       *privateKeySigner
	receiptKey    privateKeySigner
	receiptOut    string
}

func promoteCmd() *cobra.Command {
	flags := lifecycleFlags{receiptKey: defaultReceiptKeyAgent}
	cmd := &cobra.Command{
		Use:   "promote",
		Short: "Promote a contract into the active manifest with signed lifecycle receipts",
		Long: `Promote a compiled contract hash into the active manifest store.

The command validates the candidate and syncs signed contract_promote_intent
and contract_promote_committed receipts before publishing the active manifest.
Check the active manifest to see which generation took effect. In --production
mode the roster must contain at least three active activation authorities and
the manifest must carry two distinct activation principals.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPromote(cmd, flags)
		},
	}
	addLifecycleFlags(cmd, &flags)
	cmd.Flags().StringVar(&flags.contractHash, "contract", "", "contract hash to promote (required)")
	cmd.Flags().StringVar(&flags.selector, "selector", "", "selector target: agent name, agent glob, or 'default' (required)")
	cmd.Flags().StringVar(&flags.intentID, "intent-id", "", "promotion intent id; defaults to a UUIDv7")
	_ = cmd.MarkFlagRequired("contract")
	_ = cmd.MarkFlagRequired("selector")
	return cmd
}

func rollbackCmd() *cobra.Command {
	flags := lifecycleFlags{receiptKey: defaultReceiptKeyAgent}
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Rollback to an accepted manifest with signed lifecycle receipts",
		Long: `Rollback to a previously accepted manifest.

The command validates a new generation with the target manifest's selectors
and syncs signed contract_rollback_authorized and contract_rollback_committed
receipts before publishing it. Check the active manifest to see which
generation took effect. In --production mode the roster must contain at least
three active activation authorities and the manifest must carry two distinct
activation principals.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRollback(cmd, flags)
		},
	}
	addLifecycleFlags(cmd, &flags)
	cmd.Flags().StringVar(&flags.rollbackTarget, "to", "", "accepted manifest hash to rollback to (required)")
	cmd.Flags().StringVar(&flags.authorizationID, "authorization-id", "", "rollback authorization id; defaults to a UUIDv7")
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

func addLifecycleFlags(cmd *cobra.Command, flags *lifecycleFlags) {
	cmd.Flags().StringVar(&flags.storeDir, "contract-store", "", "existing active contract store directory (required, absolute)")
	cmd.Flags().StringVar(&flags.rosterPath, "roster", "", "signed key roster path (required)")
	cmd.Flags().StringVar(&flags.rosterRootFingerprint, "roster-root-fingerprint", "", "pinned roster-root fingerprint (required)")
	cmd.Flags().StringVar(&flags.keystore, "keystore", "", "keystore directory for activation and receipt signing")
	cmd.Flags().StringVar(&flags.activationKey, "activation-key", "", "keystore key id for the primary activation signature (required)")
	cmd.Flags().StringVar(&flags.dualControlFrom, "dual-control-from", "", "keystore key id for the second activation signature")
	cmd.Flags().StringVar(&flags.receiptKey, "receipt-key-agent", flags.receiptKey, "keystore agent name for committed lifecycle receipts")
	cmd.Flags().StringVar(&flags.receiptOut, "receipt-out", "", "signed lifecycle receipt JSONL path in an existing directory (defaults under --contract-store)")
	cmd.Flags().StringVar(&flags.environmentID, "environment-id", "", "manifest environment id; inherited from current active manifest when omitted")
	cmd.Flags().StringVar(&flags.tenant, "tenant", "", "manifest tenant; inherited from current active manifest when all environment flags are omitted; empty means unscoped")
	cmd.Flags().StringVar(&flags.deploymentID, "deployment-id", "", "manifest deployment id; inherited from current active manifest when all environment flags are omitted; empty means unscoped")
	cmd.Flags().BoolVar(&flags.production, "production", false, "enforce production activation policy")
	cmd.Flags().BoolVar(&flags.deterministic, "deterministic", false, "use deterministic timestamps and ids for tests")
	_ = cmd.MarkFlagRequired("contract-store")
	_ = cmd.MarkFlagRequired("roster")
	_ = cmd.MarkFlagRequired("roster-root-fingerprint")
	_ = cmd.MarkFlagRequired("activation-key")
}

func runPromote(cmd *cobra.Command, flags lifecycleFlags) error {
	lc, err := resolveLifecycle(flags)
	if err != nil {
		return err
	}
	current, hasCurrent, err := latestAccepted(lc.store, lc.opts)
	if err != nil {
		return err
	}
	env, err := resolveLifecycleEnvironment(flags, current, hasCurrent)
	if err != nil {
		return err
	}
	lc.opts.Environment = env
	selector, err := buildManifestSelector(flags.selector, flags.contractHash)
	if err != nil {
		return err
	}
	priorHash := genesisManifestHash
	generation := uint64(1)
	if hasCurrent {
		priorHash = current.ManifestHash
		generation = current.Envelope.Body.Generation + 1
	}
	body, err := activeManifestBody([]contract.ManifestSelector{selector}, generation, priorHash, env, lc.now)
	if err != nil {
		return err
	}
	envelope, err := signManifestEnvelope(body, lc)
	if err != nil {
		return err
	}
	if err := activation.ValidateManifestDualControl(envelope.Signatures, lc.roster, lc.now, lc.policy); err != nil {
		return err
	}
	targetHash, err := contractstore.ActiveManifestHash(body)
	if err != nil {
		return err
	}
	intentID := lifecycleID(flags.intentID, flags.deterministic, "promote-intent")
	intentReceipt, err := activation.SignReceipt(
		contractreceipt.PayloadContractPromoteIntent,
		activation.PromoteIntentPayload(targetHash, generation, priorHash, intentID),
		lifecycleReceiptContext(intentID, lc.now, targetHash, flags.contractHash, selector.SelectorID, generation, lc.activationKey.KeyID(), "learn promote"),
		lc.activationKey,
		signing.PurposeContractActivationSigning,
	)
	if err != nil {
		return err
	}
	const committedKind = contractreceipt.PayloadContractPromoteCommitted
	record := func(validationErr error) error {
		outcome, reason := lifecycleValidationOutcome(validationErr)
		committedReceipt, err := activation.SignReceipt(
			committedKind,
			activation.PromoteCommittedPayload(targetHash, priorHash, intentID, outcome, reason),
			lifecycleReceiptContext(intentID+"-committed", lc.now, targetHash, flags.contractHash, selector.SelectorID, generation, "learn", "learn promote"),
			lc.receiptKey,
			signing.PurposeReceiptSigning,
		)
		if err != nil {
			return err
		}
		return appendLifecycleReceiptsWithSync(lc.receiptOut, flags.receiptSync, intentReceipt, committedReceipt)
	}
	if err := writeAndAcceptManifest(lc.store, envelope, lc.opts, priorHash, generation-1, record); err != nil {
		return err
	}
	emitAuditEvent(cmd, auditEvent{
		Event:           "learn_promote",
		SignerKeyID:     lc.activationKey.KeyID(),
		Manifest:        targetHash,
		Output:          lc.receiptOut,
		ReceiptsEmitted: 2,
	})
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "promote: manifest %s generation %d active\n", targetHash, generation)
	return nil
}

func runRollback(cmd *cobra.Command, flags lifecycleFlags) error {
	lc, err := resolveLifecycle(flags)
	if err != nil {
		return err
	}
	current, hasCurrent, err := latestAccepted(lc.store, lc.opts)
	if err != nil {
		return err
	}
	if !hasCurrent {
		return fmt.Errorf("learn rollback: no accepted manifest is available")
	}
	env, err := resolveLifecycleEnvironment(flags, current, hasCurrent)
	if err != nil {
		return err
	}
	lc.opts.Environment = env
	target, err := lc.store.Accepted(flags.rollbackTarget, lc.opts)
	if err != nil {
		return fmt.Errorf("learn rollback: load target manifest: %w", err)
	}
	generation := current.Envelope.Body.Generation + 1
	body := target.Envelope.Body
	body.Generation = generation
	body.PriorManifestHash = current.ManifestHash
	body.RollbackTarget = target.ManifestHash
	body.SignedAt = lc.now
	rollbackManifestHash, err := contractstore.ActiveManifestHash(body)
	if err != nil {
		return err
	}
	envelope, err := signManifestEnvelope(body, lc)
	if err != nil {
		return err
	}
	if err := activation.ValidateManifestDualControl(envelope.Signatures, lc.roster, lc.now, lc.policy); err != nil {
		return err
	}
	authID := lifecycleID(flags.authorizationID, flags.deterministic, "rollback-authorization")
	authPayload, err := activation.RollbackAuthorizedPayload(target.ManifestHash, current.Envelope.Body.Generation, manifestSignatureStrings(envelope.Signatures), authID)
	if err != nil {
		return err
	}
	authReceipt, err := activation.SignReceipt(
		contractreceipt.PayloadContractRollbackAuthorized,
		authPayload,
		lifecycleReceiptContext(authID, lc.now, rollbackManifestHash, "", "", generation, lc.activationKey.KeyID(), "learn rollback"),
		lc.activationKey,
		signing.PurposeContractActivationSigning,
	)
	if err != nil {
		return err
	}
	const committedKind = contractreceipt.PayloadContractRollbackCommitted
	record := func(validationErr error) error {
		outcome, reason := lifecycleValidationOutcome(validationErr)
		commitPayload, err := activation.RollbackCommittedPayload(target.ManifestHash, current.ManifestHash, authID, outcome, reason)
		if err != nil {
			return err
		}
		commitReceipt, err := activation.SignReceipt(
			committedKind,
			commitPayload,
			lifecycleReceiptContext(authID+"-committed", lc.now, rollbackManifestHash, "", "", generation, "learn", "learn rollback"),
			lc.receiptKey,
			signing.PurposeReceiptSigning,
		)
		if err != nil {
			return err
		}
		return appendLifecycleReceiptsWithSync(lc.receiptOut, flags.receiptSync, authReceipt, commitReceipt)
	}
	if err := writeAndAcceptManifest(lc.store, envelope, lc.opts, current.ManifestHash, current.Envelope.Body.Generation, record); err != nil {
		return err
	}
	emitAuditEvent(cmd, auditEvent{
		Event:           "learn_rollback",
		SignerKeyID:     lc.activationKey.KeyID(),
		Manifest:        rollbackManifestHash,
		Output:          lc.receiptOut,
		ReceiptsEmitted: 2,
	})
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "rollback: manifest %s reactivated as generation %d\n", target.ManifestHash, generation)
	return nil
}

func resolveLifecycle(flags lifecycleFlags) (lifecycleContext, error) {
	storeDir, err := existingLifecycleStore(flags.storeDir)
	if err != nil {
		return lifecycleContext{}, err
	}
	roster, err := signing.LoadRoster(flags.rosterPath, flags.rosterRootFingerprint)
	if err != nil {
		return lifecycleContext{}, fmt.Errorf("learn lifecycle: load roster: %w", err)
	}
	now := time.Now().UTC()
	if flags.deterministic {
		now = time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	}
	policy := activation.Policy{Production: flags.production}
	if flags.production && flags.dualControlFrom == "" {
		return lifecycleContext{}, fmt.Errorf("%w: --dual-control-from is required in --production", activation.ErrDualControl)
	}
	if err := activation.ValidateProductionAuthorityPool(roster, now, policy); err != nil {
		return lifecycleContext{}, err
	}
	primary, err := loadLifecycleSigner(flags.keystore, flags.activationKey)
	if err != nil {
		return lifecycleContext{}, err
	}
	if err := roster.AuthorizeSignerForPayload(string(contractreceipt.PayloadContractPromoteIntent), primary.KeyID(), now); err != nil {
		return lifecycleContext{}, fmt.Errorf("learn lifecycle: activation signer %q: %w", primary.KeyID(), err)
	}
	var dual *privateKeySigner
	if flags.dualControlFrom != "" {
		secondary, secErr := loadLifecycleSigner(flags.keystore, flags.dualControlFrom)
		if secErr != nil {
			return lifecycleContext{}, secErr
		}
		if authErr := roster.AuthorizeSignerForPayload(string(contractreceipt.PayloadContractPromoteIntent), secondary.KeyID(), now); authErr != nil {
			return lifecycleContext{}, fmt.Errorf("learn lifecycle: activation signer %q: %w", secondary.KeyID(), authErr)
		}
		dual = &secondary
		if !flags.production {
			policy.RequiredSignatures = 2
		}
	}
	receiptKey, err := loadLifecycleSigner(flags.keystore, flags.receiptKey)
	if err != nil {
		return lifecycleContext{}, err
	}
	if err := roster.AuthorizeSignerForPayload(string(contractreceipt.PayloadContractPromoteCommitted), receiptKey.KeyID(), now); err != nil {
		return lifecycleContext{}, fmt.Errorf("learn lifecycle: receipt signer %q: %w", receiptKey.KeyID(), err)
	}
	receiptOut := flags.receiptOut
	if receiptOut == "" {
		receiptOut = filepath.Join(storeDir, defaultLifecycleReceiptOut)
	}
	receiptOut, err = prepareLifecycleReceiptPath(receiptOut, directorysync.Sync)
	if err != nil {
		return lifecycleContext{}, err
	}
	protected := map[string]string{
		"the activation signing key": primary.keyID,
		"the receipt signing key":    receiptKey.keyID,
	}
	if dual != nil {
		protected["the dual-control signing key"] = dual.keyID
	}
	outputs := map[string]string{"--receipt-out": receiptOut}
	protectedFiles := cliutil.ExistingFileLabels("--roster", []string{flags.rosterPath})
	protectedFiles["the active manifest"] = filepath.Join(storeDir, "active.json")
	protectedFiles["the activation journal"] = filepath.Join(storeDir, ".activation_journal.jsonl")
	if err := cliutil.RefuseOutputAliases(protectedFiles, outputs); err != nil {
		return lifecycleContext{}, err
	}
	if err := refuseOutputsOverKeystoreKeys(flags.keystore, protected, outputs); err != nil {
		return lifecycleContext{}, err
	}
	return lifecycleContext{
		store:         contractstore.New(storeDir),
		opts:          contractstore.Options{Roster: roster, MinSignatures: activation.RequiredSignatures(policy), Now: func() time.Time { return now }},
		roster:        roster,
		now:           now,
		policy:        policy,
		activationKey: primary,
		dualKey:       dual,
		receiptKey:    receiptKey,
		receiptOut:    receiptOut,
	}, nil
}

func loadLifecycleSigner(keystoreDir, keyID string) (privateKeySigner, error) {
	if keyID == "" {
		return privateKeySigner{}, fmt.Errorf("learn lifecycle: signer key id is required")
	}
	dir, err := cliutil.ResolveKeystoreDir(keystoreDir)
	if err != nil {
		return privateKeySigner{}, err
	}
	priv, err := signing.NewKeystore(dir).LoadPrivateKey(keyID)
	if err != nil {
		return privateKeySigner{}, fmt.Errorf("load lifecycle signing key for %q: %w", keyID, err)
	}
	return privateKeySigner{keyID: keyID, key: priv}, nil
}

func refuseOutputsOverKeystoreKeys(keystoreDir string, protectedAgents map[string]string, outputs map[string]string) error {
	dir, err := cliutil.ResolveKeystoreDir(keystoreDir)
	if err != nil {
		return err
	}
	ks := signing.NewKeystore(dir)
	protected := make(map[string]string, len(protectedAgents))
	for label, agentName := range protectedAgents {
		if agentName == "" {
			continue
		}
		keyPath, err := ks.PrivateKeyPath(agentName)
		if err != nil {
			return err
		}
		protected[label] = keyPath
	}
	if len(protected) == 0 {
		return nil
	}
	return cliutil.RefuseOutputAliases(protected, outputs)
}

func latestAccepted(st contractstore.Store, opts contractstore.Options) (contractstore.State, bool, error) {
	current, err := st.LatestAcceptedHistory(opts)
	if err == nil {
		return current, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return contractstore.State{}, false, nil
	}
	return contractstore.State{}, false, err
}

func resolveLifecycleEnvironment(flags lifecycleFlags, current contractstore.State, hasCurrent bool) (contract.Environment, error) {
	provided := flags.environmentID != "" || flags.tenant != "" || flags.deploymentID != ""
	if !provided && hasCurrent {
		return current.Envelope.Body.Environment, nil
	}
	if flags.environmentID == "" {
		return contract.Environment{}, fmt.Errorf("learn lifecycle: --environment-id is required without an accepted manifest")
	}
	env := contract.Environment{ID: flags.environmentID, Tenant: flags.tenant, DeploymentID: flags.deploymentID}
	if hasCurrent && env != current.Envelope.Body.Environment {
		return contract.Environment{}, fmt.Errorf("learn lifecycle: environment does not match accepted manifest")
	}
	return env, nil
}

func buildManifestSelector(selectorValue, contractHash string) (contract.ManifestSelector, error) {
	if contractHash == "" {
		return contract.ManifestSelector{}, fmt.Errorf("learn promote: --contract is required")
	}
	if selectorValue == "" {
		return contract.ManifestSelector{}, fmt.Errorf("learn promote: --selector is required")
	}
	selector := contract.ManifestSelector{ContractHash: contractHash}
	switch {
	case selectorValue == "default":
		selector.Default = true
	case strings.ContainsAny(selectorValue, "*?"):
		selector.AgentGlob = selectorValue
	default:
		selector.Agent = selectorValue
	}
	id, err := selector.ComputeSelectorID()
	if err != nil {
		return contract.ManifestSelector{}, err
	}
	selector.SelectorID = id
	return selector, nil
}

func activeManifestBody(selectors []contract.ManifestSelector, generation uint64, priorHash string, env contract.Environment, now time.Time) (contract.ActiveManifest, error) {
	selectorSetHash, err := contract.ComputeSelectorSetHash(selectors)
	if err != nil {
		return contract.ActiveManifest{}, err
	}
	body := contract.ActiveManifest{
		SchemaVersion:     1,
		ManifestKind:      contract.ManifestKindActivation,
		Generation:        generation,
		PriorManifestHash: priorHash,
		SelectorSetHash:   selectorSetHash,
		Environment:       env,
		Selectors:         selectors,
		HistoryRoot:       emptyHistoryRootHash,
		SignedAt:          now,
	}
	if err := body.Validate(); err != nil {
		return contract.ActiveManifest{}, err
	}
	return body, nil
}

func signManifestEnvelope(body contract.ActiveManifest, lc lifecycleContext) (contract.ActiveManifestEnvelope, error) {
	signers := []privateKeySigner{lc.activationKey}
	if lc.dualKey != nil {
		signers = append(signers, *lc.dualKey)
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		return contract.ActiveManifestEnvelope{}, err
	}
	signatures := make([]contract.ManifestSignature, 0, len(signers))
	for _, signer := range signers {
		key, err := lc.roster.ResolveKey(signer.KeyID(), lc.now)
		if err != nil {
			return contract.ActiveManifestEnvelope{}, err
		}
		sig := ed25519.Sign(signer.key, preimage)
		signatures = append(signatures, contract.ManifestSignature{
			KeyID:      signer.KeyID(),
			Principal:  key.Principal,
			KeyPurpose: signing.PurposeContractActivationSigning.String(),
			Algorithm:  "ed25519",
			Signature:  "ed25519:" + hex.EncodeToString(sig),
		})
	}
	return contract.ActiveManifestEnvelope{Body: body, Signatures: signatures}, nil
}

func lifecycleValidationOutcome(err error) (outcome, reason string) {
	if err != nil {
		return lifecycleOutcomeRejected, err.Error()
	}
	return lifecycleOutcomeAccepted, ""
}

func writeAndAcceptManifest(st contractstore.Store, envelope contract.ActiveManifestEnvelope, opts contractstore.Options, previousHash string, previousGeneration uint64, recordValidation func(error) error) error {
	raw, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal active manifest: %w", err)
	}
	writeOpts := opts
	writeOpts.PreviousHash = previousHash
	writeOpts.PreviousGeneration = previousGeneration
	if _, err := st.WriteActiveRecorded(raw, writeOpts, recordValidation); err != nil {
		return err
	}
	if _, err := st.Reload(writeOpts); err != nil {
		return err
	}
	return nil
}

func lifecycleID(value string, deterministic bool, label string) string {
	if value != "" {
		return value
	}
	if deterministic {
		return label + "-deterministic"
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}

func lifecycleReceiptContext(eventID string, now time.Time, activeManifestHash, contractHash, selectorID string, generation uint64, principal, actor string) activation.ReceiptContext {
	return activation.ReceiptContext{
		EventID:            eventID,
		Timestamp:          now,
		Principal:          principal,
		Actor:              actor,
		ActiveManifestHash: activeManifestHash,
		ContractHash:       contractHash,
		SelectorID:         selectorID,
		ContractGeneration: generation,
	}
}

func existingLifecycleStore(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("--contract-store must be an absolute path: %q", path)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("--contract-store must name an existing directory %q: %w", clean, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("--contract-store must be a directory with no symlink at its final component: %q", clean)
	}
	return clean, nil
}

func existingLifecycleReceiptPath(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("--receipt-out must be an absolute path: %q", path)
	}
	dir := filepath.Dir(clean)
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("--receipt-out parent %q must already exist: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("--receipt-out parent %q must be a directory", dir)
	}
	return resolveOut(clean, clean)
}

// Require a provisioned receipt directory. Sync its readable ancestors too,
// while permitting search-only ancestry above the receipt directory.
func prepareLifecycleReceiptPath(path string, syncDir func(string) error) (string, error) {
	clean, err := existingLifecycleReceiptPath(path)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(clean)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("resolve lifecycle receipt directory: %w", err)
	}
	synced := make(map[string]bool)
	for _, base := range []string{dir, resolved} {
		for current := base; ; current = filepath.Dir(current) {
			if !synced[current] {
				err := syncDir(current)
				if err == nil {
					synced[current] = true
				} else if current == base || !errors.Is(err, os.ErrPermission) {
					return "", fmt.Errorf("sync lifecycle receipt directory %s: %w", current, err)
				}
			}
			if filepath.Dir(current) == current {
				break
			}
		}
	}
	return clean, nil
}

type lifecycleReceiptSync struct {
	file func(*os.File) error
	dir  func(string) error
}

func appendLifecycleReceipts(path string, receipts ...contractreceipt.EvidenceReceipt) error {
	return appendLifecycleReceiptsWithSync(path, lifecycleReceiptSync{}, receipts...)
}

func appendLifecycleReceiptsWithSync(path string, syncReceipt lifecycleReceiptSync, receipts ...contractreceipt.EvidenceReceipt) error {
	if syncReceipt.file == nil {
		syncReceipt.file = (*os.File).Sync
	}
	if syncReceipt.dir == nil {
		syncReceipt.dir = directorysync.Sync
	}
	clean, err := existingLifecycleReceiptPath(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Clean(clean), os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lifecycle receipts: %w", err)
	}
	// Validation and recording share the store lock. An interrupted encode
	// can leave the next receipt joined to the previous partial line.
	if err := checkLifecycleReceiptTail(f); err != nil {
		_ = f.Close()
		return err
	}
	enc := json.NewEncoder(f)
	for _, receipt := range receipts {
		if err := enc.Encode(receipt); err != nil {
			_ = f.Close()
			return fmt.Errorf("write lifecycle receipt to %q: %w", clean, err)
		}
	}
	if err := syncReceipt.file(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync lifecycle receipts: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close lifecycle receipts: %w", err)
	}
	if err := syncReceipt.dir(filepath.Dir(clean)); err != nil {
		return fmt.Errorf("sync lifecycle receipt directory: %w", err)
	}
	return nil
}

func checkLifecycleReceiptTail(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat lifecycle receipts: %w", err)
	}
	if info.Size() == 0 {
		return nil
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], info.Size()-1); err != nil {
		return fmt.Errorf("read lifecycle receipt tail: %w", err)
	}
	if last[0] != '\n' {
		return fmt.Errorf("lifecycle receipt file %q has an incomplete final JSONL record (preserve it and retry with --receipt-out pointing to a new file)", f.Name())
	}
	return nil
}

func manifestSignatureStrings(signatures []contract.ManifestSignature) []string {
	out := make([]string, 0, len(signatures))
	for _, sig := range signatures {
		out = append(out, sig.Signature)
	}
	return out
}
