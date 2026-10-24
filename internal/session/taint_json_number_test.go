// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestMCPJSONNumberPathClassification(t *testing.T) {
	t.Parallel()

	protected := []string{"*/auth/*", "*/security/*", "*/.env*"}
	elevated := []string{"*/config/*", "*/middleware*"}
	paths := []struct {
		path        string
		class       ActionClass
		sensitivity ActionSensitivity
	}{
		{"/repo/auth/middleware.go", ActionClassWrite, SensitivityProtected},
		{"/repo/security/policy.go", ActionClassWrite, SensitivityProtected},
		{"/repo/.env.production", ActionClassSecret, SensitivityProtected},
		{"/repo/config/settings.go", ActionClassWrite, SensitivityElevated},
		{"/repo/middleware.go", ActionClassWrite, SensitivityElevated},
	}
	numbers := []struct{ name, value string }{
		{"ordinary", "1.5"},
		{"positive_exponent", "1e999"},
		{"negative_exponent", "-1e999"},
		{"small_exponent", "1e-999"},
		{"large_integer", strings.Repeat("9", 400)},
	}
	shapes := []struct{ name, format string }{
		{"top_level", `{"path":%q,"content":"x","n":%s}`},
		{"nested_number", `{"path":%q,"content":"x","extra":[{"n":[%s]}]}`},
		{"nested_target", `{"items":[{"path":%q,"content":"x","extra":{"n":%s}}]}`},
	}
	for _, target := range paths {
		for _, shape := range shapes {
			for _, failSafe := range []bool{false, true} {
				opts := ClassificationOptions{FailSafe: failSafe}
				baseline := ClassifyMCPToolCallWithOptions("write_file", fmt.Sprintf(shape.format, target.path, "1.5"), protected, elevated, opts)
				for _, number := range numbers {
					t.Run(fmt.Sprintf("%s/%s/failsafe_%t/%s", target.path, shape.name, failSafe, number.name), func(t *testing.T) {
						args := fmt.Sprintf(shape.format, target.path, number.value)
						got := ClassifyMCPToolCallWithOptions("write_file", args, protected, elevated, opts)
						if got.Class != target.class || got.Sensitivity != target.sensitivity || got.ActionRef != target.path || !got.Confident {
							t.Fatalf("classification = %+v, want %s/%s ref=%q confident", got, target.class, target.sensitivity, target.path)
						}
						if !reflect.DeepEqual(got, baseline) {
							t.Fatalf("classification = %+v, ordinary number = %+v", got, baseline)
						}
						for _, profile := range []string{"balanced", "strict"} {
							decision := (PolicyMatrix{Profile: profile}).EvaluateWithOptions(TaintExternalUntrusted, got.Class, got.Sensitivity, AuthorityUserBroad, PolicyEvaluateOptions{
								FailSafeClassification: failSafe, ClassificationConfident: got.Confident,
							})
							want := PolicyAsk
							if profile == "balanced" && target.sensitivity == SensitivityElevated {
								want = PolicyAllow
							}
							if decision.Decision != want {
								t.Fatalf("%s decision = %+v, want %s", profile, decision, want)
							}
						}
					})
				}
			}
		}
	}
}

func TestMCPMalformedWriteClassification(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, args, ref string }{
		{"incomplete", `{"path":"/repo/auth/middleware.go","n":`, `{"path":"/repo/auth/middleware.go","n":`},
		{"trailing_data", `{"path":"/repo/auth/middleware.go"} false`, `{"path":"/repo/auth/middleware.go"} false`},
		{"adjacent_documents", `{"path":"/repo/auth/middleware.go"}{}`, `{"path":"/repo/auth/middleware.go"}{}`},
		{"invalid_number", `{"path":"/repo/auth/middleware.go","n":1e}`, `{"path":"/repo/auth/middleware.go","n":1e}`},
		{"raw_path", "/tmp/legacy.txt", "/tmp/legacy.txt"},
	}
	for _, tt := range tests {
		for _, failSafe := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failsafe_%t", tt.name, failSafe), func(t *testing.T) {
				got := ClassifyMCPToolCallWithOptions("write_file", tt.args, []string{"*/auth/*"}, nil, ClassificationOptions{FailSafe: failSafe})
				if got.Class != ActionClassWrite || got.Sensitivity != SensitivityProtected || got.Confident || got.ActionRef != tt.ref {
					t.Fatalf("classification = %+v, want write/protected ref=%q low confidence", got, tt.ref)
				}
				if !slices.Equal(got.OverrideRefs, compactNonEmpty(tt.ref)) {
					t.Fatalf("override refs = %q, want %q", got.OverrideRefs, compactNonEmpty(tt.ref))
				}
				decision := (PolicyMatrix{Profile: "balanced"}).EvaluateWithOptions(TaintExternalUntrusted, got.Class, got.Sensitivity, AuthorityUserBroad, PolicyEvaluateOptions{
					FailSafeClassification: failSafe, ClassificationConfident: got.Confident,
				})
				if decision.Decision != PolicyAsk || decision.Reason != "protected_write_after_untrusted_external_exposure" {
					t.Fatalf("decision = %+v, want protected write approval", decision)
				}
			})
		}
	}
}

func TestMCPJSONNumberStringExtraction(t *testing.T) {
	t.Parallel()

	for _, number := range []string{"1.5", "1e999", "-1e999", "1e-999", strings.Repeat("9", 400)} {
		t.Run(number, func(t *testing.T) {
			raw := `{"outer":[{"path":"/repo/auth/middleware.go","n":` + number + `}]}`
			got := flattenJSONStrings(raw)
			want := []string{"outer", "n", "path", "/repo/auth/middleware.go"}
			if !slices.Equal(got, want) {
				t.Fatalf("strings = %q, want %q", got, want)
			}
		})
	}
}

// Absent and null MCP arguments reach the classifier as "" (the frame parser
// normalizes both). They name no target, so they must classify exactly like
// an explicit empty object under either fail-safe setting rather than taking
// the malformed-input path.
func TestMCPEmptyArgumentsMatchEmptyObject(t *testing.T) {
	t.Parallel()

	for _, failSafe := range []bool{false, true} {
		t.Run(fmt.Sprintf("failsafe_%t", failSafe), func(t *testing.T) {
			opts := ClassificationOptions{FailSafe: failSafe}
			want := ClassifyMCPToolCallWithOptions("write_file", "{}", []string{"*/auth/*"}, nil, opts)
			got := ClassifyMCPToolCallWithOptions("write_file", "", []string{"*/auth/*"}, nil, opts)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("empty arguments = %+v, want {} classification %+v", got, want)
			}
			wantSensitivity := SensitivityNormal
			if failSafe {
				wantSensitivity = SensitivityProtected
			}
			if got.Class != ActionClassWrite || got.Sensitivity != wantSensitivity || got.Confident {
				t.Fatalf("classification = %+v, want write/%s low confidence", got, wantSensitivity)
			}
		})
	}
}
