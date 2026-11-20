// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"
)

const (
	wheelEntropyHost  = "files.pkg.example"
	cryptographyWheel = "cryptography-43.0.1-cp39-abi3-manylinux_2_28_x86_64.whl"
	cpythonWheelTags  = "-cp39-abi3-manylinux_2_28_x86_64.whl"
	pathEntropyReason = "high entropy path segment"
)

func TestWheelFilenameEntropyScan(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	for _, tc := range []struct {
		name, filename string
	}{
		{"cryptography", cryptographyWheel},
		{"SQLAlchemy", "SQLAlchemy-2.0.36-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"},
		{"MarkupSafe", "MarkupSafe-3.0.2-cp39-cp39-manylinux_2_5_i686.manylinux1_i686.manylinux_2_17_i686.manylinux2014_i686.whl"},
		{"grpcio tools", "grpcio_tools-1.68.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"},
		{"PySide6 Essentials", "PySide6_Essentials-6.8.0.2-cp39-abi3-manylinux_2_28_x86_64.whl"},
		{"metadata sidecar", cryptographyWheel + ".metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if entropy, blocked := s.pathSegmentEntropy(tc.filename); !blocked {
				t.Fatalf("whole-segment entropy = %.2f, want > %.2f", entropy, s.entropyThreshold)
			}
			result := s.Scan(t.Context(), "https://"+wheelEntropyHost+"/packages/"+tc.filename)
			if !result.Allowed {
				t.Fatalf("wheel blocked by %s: %s", result.Scanner, result.Reason)
			}
		})
	}
}

func TestWheelFilenameEntropySubject(t *testing.T) {
	const exampleStem = "example-1.0"
	for _, tc := range []struct {
		name, filename, stem string
		wheel                bool
	}{
		{"earlier spelling and build", "Example.Project-1!2.3rc1.post2.dev3+vendor.1-42_build-py2.py3-none-any.whl", "Example.Project-1!2.3rc1.post2.dev3+vendor.1-42_build", true},
		{"unknown platform", exampleStem + "-cp315-cp315t.abi3t-none.whl", "", true},
		{"free-threaded Windows", exampleStem + "-cp315-cp315t.abi3t-win_arm64.whl", exampleStem, true},
		{"musllinux", exampleStem + "-cp312-cp312-musllinux_1_2_aarch64.whl", exampleStem, true},
		{"macOS", exampleStem + "-cp312-abi3-macosx_11_0_universal2.whl", exampleStem, true},
		{"PyPy", exampleStem + "-pp310-pypy310_pp73-manylinux_2_28_x86_64.whl", exampleStem, true},
		{"Android", exampleStem + "-cp313-cp313-android_27_arm64_v8a.whl", exampleStem, true},
		{"iOS", exampleStem + "-cp313-cp313-ios_13_0_arm64_iphonesimulator.whl", exampleStem, true},
		{"empty tag in set", "example-1.0-py2..py3-none-any.whl", "", true},
		{"bad legacy architecture", "example-1.0-cp312-abi3-manylinux1_aarch64.whl", "", true},
		{"bad version", "example-release-py3-none-any.whl", "", true},
		{"bad build", "example-1.0-build42-py3-none-any.whl", "", true},
		{"unknown suffix", "example-1.0-py3-none-any.whl.bak", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stem, wheel := wheelFilenameEntropySubject(tc.filename)
			if stem != tc.stem || wheel != tc.wheel {
				t.Fatalf("wheel stem = %q, wheel suffix = %v; want (%q, %v)", stem, wheel, tc.stem, tc.wheel)
			}
		})
	}
}

func TestWheelFilenameEntropyDenials(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	const (
		name    = "HPMJSVDRXFNLOQEUBGW"
		version = "1.0+tuvwxyz0123456789ab"
		stem    = name + "-" + version
	)
	if entropy := payloadEntropy(stem); entropy <= s.entropyThreshold ||
		payloadEntropy(name) > s.entropyThreshold || payloadEntropy(version) > s.entropyThreshold {
		t.Fatalf("split-stem fixture must exceed the threshold only when combined (combined %.2f)", entropy)
	}
	localStem := "example-1.0+" + strings.ToLower(entropyTestMixed)
	for _, tc := range []struct {
		name, path, stem string
	}{
		{"combined name and version", stem + cpythonWheelTags, stem},
		{"high-entropy local version", localStem + cpythonWheelTags, localStem},
		{"invalid Python tag", "example-1.0-py3." + entropyTestMixed + "-abi3-manylinux_2_28_x86_64.whl", ""},
		{"invalid ABI tag", "example-1.0-cp39-abi3." + entropyTestMixed + "-manylinux_2_28_x86_64.whl", ""},
		{"invalid platform tag", "example-1.0-cp39-abi3-manylinux_2_28_x86_64.manylinux_2_28_" + entropyTestMixed + ".whl", ""},
		{"wheel suffix only", entropyTestMixed + ".whl", ""},
		{"wheel in directory", cryptographyWheel + "/index", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if stem, _ := wheelFilenameEntropySubject(tc.path); stem != tc.stem {
				t.Fatalf("recognized stem = %q, want %q", stem, tc.stem)
			}
			result := s.Scan(t.Context(), "https://"+wheelEntropyHost+"/"+tc.path)
			if result.Allowed || result.Scanner != ScannerEntropy || !strings.HasPrefix(result.Reason, pathEntropyReason) {
				t.Fatalf("allowed = %v, scanner = %q, reason = %q; want path entropy block", result.Allowed, result.Scanner, result.Reason)
			}
		})
	}
}

func TestWheelFilenameEntropyHashDirectory(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	const hash = "0f1e2d3c4b5a69788796a5b4c3d2e1f0da7e6c9b50a1348f2e0b7d6a5c2f"
	if score, blocked := s.pathSegmentEntropy(hash); blocked || score > 4 {
		t.Fatalf("hash entropy = %.2f, blocked = %v; want <= 4 and allowed", score, blocked)
	}
	if result := s.Scan(t.Context(), "https://"+wheelEntropyHost+"/"+hash+"/"+cryptographyWheel); !result.Allowed {
		t.Fatalf("wheel under hash directory blocked by %s: %s", result.Scanner, result.Reason)
	}
}

func TestWheelFilenameEntropyScanEntryPoints(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	const path = wheelEntropyHost + "/" + cryptographyWheel
	for _, tc := range []struct {
		name, scheme string
		scan         func(context.Context, string) Result
	}{
		{"ordinary", "https://", s.Scan},
		{"intercept", "https://", func(ctx context.Context, raw string) Result {
			return s.ScanWithReservation(ctx, raw, nil)
		}},
		{"websocket", "wss://", s.ScanWebSocket},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if result := tc.scan(t.Context(), tc.scheme+path); !result.Allowed {
				t.Fatalf("wheel blocked by %s: %s", result.Scanner, result.Reason)
			}
			raw := tc.scheme + path + "/" + entropyTestMixed
			result := tc.scan(t.Context(), raw)
			if result.Allowed || result.Scanner != ScannerEntropy || !strings.HasPrefix(result.Reason, pathEntropyReason) {
				t.Fatalf("non-final wheel: allowed = %v, scanner = %q, reason = %q", result.Allowed, result.Scanner, result.Reason)
			}
		})
	}
}
