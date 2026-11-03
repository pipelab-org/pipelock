// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

// Decision describes one URL check, independently of transport enforcement.
type Decision uint8

const (
	// DecisionNotEvaluated means the pipeline returned before entering this check.
	DecisionNotEvaluated Decision = 0
	// DecisionAllowed means the check returned an allow, including configured bypasses.
	DecisionAllowed Decision = 1 << iota
	// DecisionFired means the check produced a finding.
	DecisionFired
	// DecisionBlocked means the check returned a refusal.
	DecisionBlocked
	// DecisionRelieved means an observed finding was allowed by an allowance.
	DecisionRelieved
)

const (
	urlContext = iota
	urlLength
	urlParser
	urlScheme
	urlCRLF
	urlTraversal
	urlAllowlist
	urlBlocklist
	urlCoreSSRF
	urlCoreDLP
	urlDLP
	urlEntropy
	urlSubdomainEntropy
	urlNested
	urlSSRF
	urlRateLimit
	urlDataBudget
	urlCheckCount
)

// DecisionCheckNestedDestination labels the composite check that scans
// destinations nested in query values. It has its own name because the
// scanner's ScannerAll label reads as an aggregate of every check.
const DecisionCheckNestedDestination = "nested_destination"

// URLDecisions holds bounded execution state for the top-level URL checks.
// It contains no request data and is excluded from result serialization.
// Nested destinations are one composite check with part=url_query;
// individual nested subchecks are not represented.
type URLDecisions struct {
	valid  bool
	checks [urlCheckCount]Decision
}

// Range visits each check once. A zero-value trace represents no URL scan.
func (d URLDecisions) Range(visit func(check, part string, outcome Decision)) {
	if !d.valid {
		return
	}
	names := [...]string{
		ScannerContext, ScannerLength, ScannerParser, ScannerScheme,
		ScannerCRLF, ScannerPathTraversal, ScannerAllowlist, ScannerBlocklist,
		ScannerCoreSSRF, ScannerCoreDLP, ScannerDLP, ScannerEntropy,
		ScannerSubdomainEntropy, DecisionCheckNestedDestination, ScannerSSRF, ScannerRateLimit, ScannerDataBudget,
	}
	for i, name := range names {
		part := "url"
		if i == urlNested {
			part = "url_query"
		}
		visit(name, part, d.checks[i])
	}
}

func (d *URLDecisions) record(check int, result Result) {
	// A cancelled request context aborts whichever check was running, so the
	// refusal belongs to the context, not to that check. The check reached no
	// verdict and stays not evaluated.
	if !result.Allowed && result.Scanner == ScannerContext {
		d.checks[urlContext] = DecisionFired | DecisionBlocked
		return
	}
	outcome := DecisionAllowed
	if !result.Allowed {
		outcome = DecisionFired | DecisionBlocked
	}
	if len(result.WarnMatches) > 0 {
		outcome |= DecisionFired
	}
	if result.relief {
		outcome |= DecisionFired | DecisionRelieved
	}
	d.checks[check] = outcome
}
