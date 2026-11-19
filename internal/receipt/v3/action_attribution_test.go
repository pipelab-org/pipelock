// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
)

func TestSetAttributionRedaction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report *redact.Report
	}{
		{name: "missing"},
		{name: "not applied", report: &redact.Report{TotalRedactions: 2}},
		{name: "zero redactions", report: &redact.Report{Applied: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action := Action{Redaction: &Redaction{}}
			action.SetAttribution(receipt.EmitOpts{RedactionReport: tc.report})
			if action.Redaction != nil {
				t.Fatalf("redaction attribution = %+v, want none", action.Redaction)
			}
		})
	}

	var action Action
	action.SetAttribution(receipt.EmitOpts{
		RedactionProfile: "default",
		RedactionReport: &redact.Report{
			Applied: true, TotalRedactions: 3, Provider: "vendor", Parser: "json",
			ByClass: map[redact.Class]int{"email": 2, "address": 1},
		},
	})
	got := action.Redaction
	want := []RedactionClass{{Class: "address", Count: 1}, {Class: "email", Count: 2}}
	if got == nil || got.Profile != "default" || got.Provider != "vendor" || got.Parser != "json" ||
		got.TotalRedactions == nil || *got.TotalRedactions != 3 || !slices.Equal(got.Classes, want) {
		t.Fatalf("redaction attribution = %+v, want profile and sorted class counts", got)
	}
}

func TestSetAttributionContractGeneration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generation uint64
		want       int64
	}{
		{name: "maximum", generation: maxInteger, want: maxInteger},
		{name: "out of range", generation: maxInteger + 1, want: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var action Action
			action.SetAttribution(receipt.EmitOpts{ContractGeneration: tc.generation})
			if action.Contract == nil || action.Contract.Generation == nil || *action.Contract.Generation != tc.want {
				t.Fatalf("contract attribution = %+v, want generation %d", action.Contract, tc.want)
			}
		})
	}
}
