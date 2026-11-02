// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
)

// aarpOptions holds resolved CLI flags for the aarp subcommand.
type aarpOptions struct {
	trustPath      string
	svidPath       string
	jsonOutput     bool
	chain          bool
	allowPrefix    bool
	expectHead     string
	expectSeq      uint64
	expectFinalSeq *uint64
}

// trustFile is the on-disk trust input shared by all four reference verifiers.
// It carries ONLY pinned, operator-controlled trust — never anything fetched
// live. trusted_keys maps a key id to its Ed25519 public key (64-hex); a
// signature whose key id is absent is reported unknown_key and never verifies.
// trust_entries maps a key id to the authority namespace it is authorized to
// assert, so a verified signature can confirm the mediator_key_pinned claim.
type trustFile struct {
	TrustedKeys  map[string]string         `json:"trusted_keys"`
	TrustEntries map[string]trustEntryFile `json:"trust_entries,omitempty"`
}

type trustEntryFile struct {
	MediatorID  string `json:"mediator_id"`
	Role        string `json:"role,omitempty"`
	TrustDomain string `json:"trust_domain,omitempty"`
}

// envelopeFatal is the --json body the verifier prints when the envelope is
// fatal to appraise at all (schema violation, profile/canon mismatch, unknown
// critical extension). It carries no appraisal because none was produced; the
// non-zero exit code is the cross-language signal the gate compares.
type envelopeFatal struct {
	EnvelopeFatal bool   `json:"envelope_fatal"`
	Error         string `json:"error,omitempty"`
}

func newAARPCmd() *cobra.Command {
	var opts aarpOptions

	cmd := &cobra.Command{
		Use:   "aarp PATH",
		Short: "Appraise an AARP v0.1 assurance envelope",
		Long: `Appraises an AARP (Agent Action Receipt Profile) v0.1 assurance envelope
against a pinned trust file. PATH points at a JSON envelope.

The appraisal reports which claims the verifier could cryptographically confirm,
grouped by axis, plus the fixed does_not_assert list. It never emits a "trusted"
or "safe" verdict. Per-signature problems (unknown suite, untrusted key, bad
signature) are reported per signature, never as an envelope rejection, so one
bad parallel signature cannot mask a good one.

Exit codes: 0 the envelope was appraised; 1 the envelope is fatal to appraise
(schema violation, profile/canon mismatch, unknown critical extension); 2 an
I/O or trust-file error; 64 a usage error. With --json the verifier prints the
cross-language comparable appraisal on stdout (or {"envelope_fatal":true} when
the envelope is fatal).

With --chain, every envelope must have a signature verified against --trust,
and the stream must start at genesis. AARP has no terminal record: exit 0
requires an independently supplied --expect-head or --expect-seq endpoint.
Otherwise the verdict is VALID PREFIX, END UNPROVEN with exit 3.
--allow-prefix returns 0 while preserving that partial verdict.`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("expect-seq") {
				opts.expectFinalSeq = &opts.expectSeq
			}
			return runAARP(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)

	cmd.Flags().StringVar(&opts.trustPath, "trust", "", "path to the pinned trust JSON (trusted_keys + trust_entries)")
	cmd.Flags().StringVar(&opts.svidPath, "svid", "", "path to the SVID attestation JSON (evidence + pinned bundle/action-time); appraises the X.509-SVID binding")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit the comparable appraisal JSON on stdout")
	cmd.Flags().BoolVar(&opts.chain, "chain", false, "PATH is a JSONL stream; authenticate every envelope and verify linkage from genesis")
	cmd.Flags().BoolVar(&opts.allowPrefix, "allow-prefix", false, "return success for a valid prefix while reporting its unproven end (--chain)")
	cmd.Flags().StringVar(&opts.expectHead, "expect-head", "", "require the final payload digest to equal this independently known hash (--chain)")
	cmd.Flags().Var(endproof.SeqFlag{Seq: &opts.expectSeq}, "expect-seq", "require this independently known final sequence (--chain)")

	return cmd
}

func runAARP(stdout, stderr io.Writer, target string, opts aarpOptions) error {
	if !opts.chain && (opts.allowPrefix || opts.expectHead != "" || opts.expectFinalSeq != nil) {
		return cliutil.ExitCodeError(exitUsage, fmt.Errorf("--allow-prefix, --expect-head and --expect-seq require --chain"))
	}
	if opts.chain && opts.svidPath != "" {
		return cliutil.ExitCodeError(exitUsage, fmt.Errorf("--svid is single-envelope only and cannot be combined with --chain"))
	}

	verifyOpts, err := loadTrustFile(opts.trustPath)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("load trust: %w", err))
	}

	// Load the SVID attestation sidecar (if any) before reading the envelope, so
	// a malformed pinned bundle is reported as a config error (exit 2) rather
	// than entangled with envelope appraisal.
	var (
		svidEvidence *aarp.SVIDEvidence
		svidOpts     aarp.SVIDVerifyOptions
	)
	if opts.svidPath != "" {
		svidEvidence, svidOpts, err = loadSVIDFile(opts.svidPath)
		if err != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("load svid: %w", err))
		}
	}

	data, err := readVerifierFile(target)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("read envelope: %w", err))
	}

	if opts.chain {
		return runAARPChain(stdout, stderr, data, opts, verifyOpts)
	}

	env, err := aarp.Unmarshal(data)
	if err != nil {
		return emitFatal(stdout, stderr, opts.jsonOutput, err)
	}

	// With --svid, appraise the X.509-SVID binding on top of the envelope
	// appraisal; the SVID claims are added only when the binding verifies against
	// the pinned bundle. Without it, the plain envelope appraisal is unchanged and
	// byte-identical.
	var ap *aarp.Appraisal
	if svidEvidence != nil {
		ap, err = aarp.AppraiseWithSVID(env, svidEvidence, verifyOpts, svidOpts)
	} else {
		ap, err = aarp.Verify(env, verifyOpts)
	}
	if err != nil {
		return emitFatal(stdout, stderr, opts.jsonOutput, err)
	}

	comparableBytes, err := aarp.ComparableAppraisal(ap)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("render appraisal: %w", err))
	}
	if opts.jsonOutput {
		_, _ = stdout.Write(comparableBytes)
		_, _ = fmt.Fprintln(stdout)
	} else {
		emitAARPHuman(stdout, ap)
	}
	return nil
}

// runAARPChain authenticates a JSONL stream from genesis. AARP has no terminal
// record, so only an independently supplied endpoint pin proves its end.
func runAARPChain(stdout, stderr io.Writer, data []byte, opts aarpOptions, trust aarp.VerifyOptions) error {
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	envs := make([]aarp.Envelope, 0, len(lines))
	for i, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		e, err := aarp.Unmarshal(line)
		if err != nil {
			return emitFatal(stdout, stderr, opts.jsonOutput, fmt.Errorf("chain line %d: %w", i, err))
		}
		envs = append(envs, e)
	}

	report := aarpChainReport{Report: endproof.New(false, "aarp_chain"), Length: len(envs)}
	emit := func(cause error) error {
		if cause != nil {
			report.Report = endproof.New(false, "aarp_chain")
			report.Error = cause.Error()
		}
		if opts.jsonOutput {
			writeJSON(stdout, report)
		} else {
			_, _ = fmt.Fprintf(stdout, "AARP chain: %d envelopes\n%s\n", len(envs), report.Status)
			if cause != nil {
				_, _ = fmt.Fprintln(stderr, cause)
			}
		}
		if cause != nil {
			return cliutil.ExitCodeError(cliutil.ExitGeneral, cause)
		}
		return report.Require(opts.allowPrefix)
	}
	if err := aarp.VerifyChain(envs); err != nil {
		return emit(err)
	}
	report.ChainLinked = true
	if envs[0].Chain.Seq != "0" || envs[0].Chain.PriorHash != aarp.GenesisPriorHash {
		return emit(fmt.Errorf("chain does not start at genesis"))
	}
	for i, env := range envs {
		ap, err := aarp.Verify(env, trust)
		if err != nil {
			return emit(fmt.Errorf("chain envelope %d: %w", i, err))
		}
		if !ap.AssertionSigned {
			return emit(errors.New("no signature verified against pinned trust; pass --trust with the signer key"))
		}
	}
	report.SignaturesVerified = true
	tip := envs[len(envs)-1]
	head, err := tip.PayloadDigest()
	if err != nil {
		return emit(err)
	}
	seq, err := strconv.ParseUint(tip.Chain.Seq, 10, 64)
	if err != nil {
		return emit(err)
	}
	proof, err := endproof.Pin(head, seq, opts.expectHead, opts.expectFinalSeq)
	if err != nil {
		return emit(err)
	}
	report.Report = endproof.New(true, "aarp_chain", proof...)
	return emit(nil)
}

type aarpChainReport struct {
	endproof.Report
	ChainLinked        bool   `json:"chain_linked"`
	Length             int    `json:"length"`
	SignaturesVerified bool   `json:"signatures_verified"`
	Error              string `json:"error,omitempty"`
}

// emitFatal prints the envelope-fatal marker (or human text) and returns the
// exit-1 error. Fatal means the verifier could not safely appraise the envelope
// at all; it is distinct from an appraisal that reports unverified claims.
func emitFatal(stdout, stderr io.Writer, jsonMode bool, cause error) error {
	if jsonMode {
		writeJSON(stdout, envelopeFatal{EnvelopeFatal: true, Error: cause.Error()})
	} else {
		_, _ = fmt.Fprintf(stderr, "ENVELOPE FATAL: %s\n", cause.Error())
	}
	return cliutil.ExitCodeError(cliutil.ExitGeneral, cause)
}

// aarpTotalAxes is the number of axes AARP defines (identity, authority,
// integrity, freshness, transparency, deployment). The human view reports
// covered axes against this denominator so a reader sees how narrow the evidence
// is, never just how broad.
const aarpTotalAxes = 6

// emitAARPHuman renders the appraisal so a reader sees the LIMITATIONS first: the
// does_not_assert list and any overclaim risks lead, before the verified claims.
// The default human view is deliberately self-incriminating — the first thing a
// reader sees is what the evidence does NOT prove, including on a real Pipelock
// receipt. The machine form (--json) carries the same outcomes for tooling.
func emitAARPHuman(stdout io.Writer, ap *aarp.Appraisal) {
	_, _ = fmt.Fprintf(stdout, "AARP appraisal (%s)\n", ap.Profile)
	_, _ = fmt.Fprintf(stdout, "  assertion_signed: %t\n", ap.AssertionSigned)

	_, _ = fmt.Fprintln(stdout, "  does_not_assert (this appraisal never proves):")
	for _, d := range sortedCopy(ap.DoesNotAssert) {
		_, _ = fmt.Fprintf(stdout, "    - %s\n", d)
	}

	if len(ap.OverclaimRisks) > 0 {
		_, _ = fmt.Fprintln(stdout, "  overclaim_risks (do not read more into the evidence than this):")
		for _, r := range sortedCopy(ap.OverclaimRisks) {
			_, _ = fmt.Fprintf(stdout, "    - %s: %s\n", r, overclaimRiskSentence(r))
		}
	}

	_, _ = fmt.Fprintln(stdout, "  --- what the evidence mechanically supports ---")
	_, _ = fmt.Fprintf(stdout, "  verified_claims:    %v\n", ap.VerifiedClaims)
	_, _ = fmt.Fprintf(stdout, "  claimed_unverified: %v\n", ap.ClaimedUnverified)

	axes := ap.Assurance.AxesWithVerifiedClaims
	covered := "(none)"
	if len(axes) > 0 {
		covered = strings.Join(axes, ", ")
	}
	_, _ = fmt.Fprintf(stdout, "  evidence covers axes: %s (%d of %d)\n", covered, len(axes), aarpTotalAxes)

	for _, s := range ap.Signatures {
		_, _ = fmt.Fprintf(stdout, "  signature %s/%s: %s\n", s.KeyID, s.Alg, s.Status)
	}
}

// overclaimRiskSentence maps a stable overclaim-risk code to a one-line
// explanation for the human view. An unmapped code (a verifier ahead of this CLI)
// falls back to the bare code so the warning is never silently dropped.
func overclaimRiskSentence(code string) string {
	switch code {
	case aarp.RiskSignatureValidNotTransparency:
		return "a valid signature is integrity over the assertion bytes, not proof the receipt was witnessed by an external transparency log"
	case aarp.RiskSVIDIdentityNotDeploymentNonBypass:
		return "a verified signing-workload identity does not prove the deployment forced the workload's traffic through the mediator"
	case aarp.RiskChainLinkNotContiguousChain:
		return "a present chain link is a single position, not a verified contiguous stream (verify the stream with --chain)"
	default:
		return code
	}
}

// sortedCopy returns a sorted copy of in, leaving the input untouched so the
// display order never mutates the appraisal.
func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// loadTrustFile reads the pinned trust JSON into VerifyOptions. A missing path
// yields empty trust (every signature is reported unknown_key) so the verifier
// still runs and the gate can exercise the no-trust path.
func loadTrustFile(path string) (aarp.VerifyOptions, error) {
	opts := aarp.VerifyOptions{
		TrustedKeys: map[string]ed25519.PublicKey{},
		Trust:       map[string]aarp.TrustEntry{},
	}
	if path == "" {
		return opts, nil
	}
	data, err := readVerifierFile(path)
	if err != nil {
		return aarp.VerifyOptions{}, fmt.Errorf("read trust file: %w", err)
	}
	var tf trustFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tf); err != nil {
		return aarp.VerifyOptions{}, fmt.Errorf("parse trust file: %w", err)
	}
	for keyID, keyHex := range tf.TrustedKeys {
		raw, err := hex.DecodeString(keyHex)
		if err != nil {
			return aarp.VerifyOptions{}, fmt.Errorf("trusted_keys[%q]: not hex: %w", keyID, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return aarp.VerifyOptions{}, fmt.Errorf("trusted_keys[%q]: %d bytes, want %d", keyID, len(raw), ed25519.PublicKeySize)
		}
		opts.TrustedKeys[keyID] = ed25519.PublicKey(raw)
	}
	for keyID, e := range tf.TrustEntries {
		opts.Trust[keyID] = aarp.TrustEntry{
			MediatorID:  e.MediatorID,
			Role:        e.Role,
			TrustDomain: e.TrustDomain,
		}
	}
	return opts, nil
}
