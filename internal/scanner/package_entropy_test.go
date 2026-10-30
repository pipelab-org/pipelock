// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math"
	"net/url"
	"strings"
	"testing"
)

const (
	packageEntropyDebian = "libk5crypto3_1.20.1-2+deb12u5_amd64.deb"
	// Valid Alpine suffixes can still push a version above the entropy gate.
	packageEntropyAPKVersion = "1.2.3_alpha4_beta5_pre6_rc7_cvs8_svn9_git0123456789_hg1_p2-r3"
)

func TestPackageFilenameEntropySubjects(t *testing.T) {
	for _, tc := range []struct {
		name, filename, remainder, version string
	}{
		{"debian", packageEntropyDebian, "libk5crypto3__amd64.deb", "1.20.1-2+deb12u5"},
		{"udeb", "libc6-udeb_2.36-9+deb12u9_amd64.udeb", "libc6-udeb__amd64.udeb", "2.36-9+deb12u9"},
		{"native debian", "ab_1.2~rc1_all.deb", "ab__all.deb", "1.2~rc1"},
		{"debian upstream hyphen", "ab_1.2-beta-3_hurd-i386.deb", "ab__hurd-i386.deb", "1.2-beta-3"},
		{"debian one letter name", "x_1.2_all.deb", "", ""},
		{"debian uppercase name", "Ab_1.2_all.deb", "", ""},
		{"debian epoch", "ab_1:2.3_all.deb", "", ""},
		{"debian empty revision", "ab_1.2-_all.deb", "", ""},
		{"debian nondigit version", "ab_v1.2_all.deb", "", ""},
		{"debian uppercase arch", "ab_1.2_AMD64.deb", "", ""},
		{"debian empty arch", "ab_1.2_.deb", "", ""},
		{"rpm", "krb5-libs-1.21.3-3.fc41.x86_64.rpm", "krb5-libs-.x86_64.rpm", "1.21.3-3.fc41"},
		{"rpm rightmost fields", "Example-Compat-Libs-1.2~rc1^git2-3.fc41.noarch.rpm", "Example-Compat-Libs-.noarch.rpm", "1.2~rc1^git2-3.fc41"},
		{"rpm missing release", "krb5-1.2.x86_64.rpm", "", ""},
		{"rpm empty version", "krb5--3.x86_64.rpm", "", ""},
		{"rpm empty arch", "krb5-1.2-3..rpm", "", ""},
		{"apk", "py3-cryptography-43.0.3-r0.apk", "py3-cryptography-.apk", "43.0.3-r0"},
		{"apk suffixes", "ab-1.2a_rc1_git20261030-r12.apk", "ab-.apk", "1.2a_rc1_git20261030-r12"},
		{"apk nondigit version", "ab-v1.2-r0.apk", "", ""},
		{"apk unknown suffix", "ab-1.2_random1-r0.apk", "", ""},
		{"apk nonnumeric release", "ab-1.2-rx.apk", "", ""},
		{"apk uppercase name", "Ab-1.2-r0.apk", "", ""},
		{"uppercase extension", "ab_1.2_all.DEB", "", ""},
		{"extra suffix", "ab_1.2_all.deb.bin", "", ""},
		{"path prefix", "/ab_1.2_all.deb", "", ""},
		{"newline suffix", "ab_1.2_all.deb\n", "", ""},
		{"empty", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remainder, version, ok := packageFilenameEntropySubjects(tc.filename)
			if remainder != tc.remainder || version != tc.version || ok != (tc.version != "") {
				t.Fatalf("subjects = (%q, %q, %v), want (%q, %q, %v)", remainder, version, ok, tc.remainder, tc.version, tc.version != "")
			}
		})
	}
}

// packageEntropyPayload reorders alphabet with a fixed stride so the payload
// does not read as a sorted run. Every character still appears once, which is
// what pushes it over the entropy gate; Shannon entropy ignores order.
func packageEntropyPayload(alphabet string) string {
	const stride = 7 // Coprime with every alphabet length used here.
	out := make([]byte, len(alphabet))
	for i := range out {
		out[i] = alphabet[i*stride%len(alphabet)]
	}
	return string(out)
}

func TestPackageFilenameEntropyScan(t *testing.T) {
	s := newProtocolEntropyScanner(t) // config.Defaults(), with cfg.Internal = nil.
	base62 := packageEntropyPayload("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	base64url := packageEntropyPayload("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
	lower := packageEntropyPayload("abcdefghijklmnopqrstuvwxyz0123456789")
	for _, tc := range []struct {
		name, path string
		allow      bool
	}{
		{"debian reproduction", "/debian-security/pool/updates/main/k/krb5/" + strings.ReplaceAll(packageEntropyDebian, "+", "%2b"), true},
		{"debian decoded", "/pool/" + packageEntropyDebian, true},
		{"rpm", "/pool/krb5-libs-1.21.3-3.fc41.x86_64.rpm", true},
		{"apk", "/pool/py3-cryptography-43.0.3-r0.apk", true},
		{"rpm split required", "/pool/gdk-pixbuf-query-loaders-1.21.3-3.fc41.x86_64.rpm", true},
		{"apk split required", "/pool/gdk-pixbuf-query-loaders-3.7.8_rc1_git20261030-r12.apk", true},
		{"debian version payload", "/pool/ab_1" + base62 + "_all.deb", false},
		{"rpm version payload", "/pool/ab-1" + base62 + "-1.noarch.rpm", false},
		{"rpm release payload", "/pool/ab-1-" + base62 + ".noarch.rpm", false},
		{"apk version payload", "/pool/ab-1" + base62 + "-r0.apk", false},
		{"apk valid high entropy version", "/pool/ab-" + packageEntropyAPKVersion + ".apk", false},
		{"debian base64url payload", "/pool/ab_1" + base64url + "_all.deb", false},
		{"rpm base64url payload", "/pool/ab-1" + base64url + "-1.noarch.rpm", false},
		{"apk base64url payload", "/pool/ab-1" + base64url + "-r0.apk", false},
		{"debian name payload", "/pool/" + lower + "_1_all.deb", false},
		{"rpm name payload", "/pool/" + base62 + "-1-1.noarch.rpm", false},
		{"apk name payload", "/pool/" + lower + "-1-r0.apk", false},
		{"nongrammar filename", "/pool/" + base62 + ".bin", false},
		{"nonfinal package", "/pool/" + packageEntropyDebian + "/tail", false},
		{"nonfinal rpm", "/pool/gdk-pixbuf-query-loaders-1.21.3-3.fc41.x86_64.rpm/tail", false},
		{"nonfinal apk", "/pool/gdk-pixbuf-query-loaders-3.7.8_rc1_git20261030-r12.apk/tail", false},
		{"trailing slash", "/pool/" + packageEntropyDebian + "/", false},
		{"query payload", "/pool/" + packageEntropyDebian + "?ref=" + base62, false},
	} {
		for _, scheme := range []string{"http", "https"} {
			t.Run(tc.name+"/"+scheme, func(t *testing.T) {
				raw := scheme + "://deb.debian.org" + tc.path
				got := s.Scan(t.Context(), raw)
				if got.Allowed != tc.allow || !tc.allow && got.Scanner != ScannerEntropy {
					t.Fatalf("allowed = %v, scanner = %q, reason %q; want allowed = %v", got.Allowed, got.Scanner, got.Reason, tc.allow)
				}
			})
		}
	}
}

func TestPackageFilenameEntropyScoresBothSubjects(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	payload := packageEntropyPayload("abcdefghijklmnopqrstuvwxyz0123456789")
	for _, filename := range []string{
		packageEntropyDebian,
		"gdk-pixbuf-query-loaders-1.21.3-3.fc41.x86_64.rpm",
		"gdk-pixbuf-query-loaders-3.7.8_rc1_git20261030-r12.apk",
		"ab_1" + payload + "_all.deb",
		payload + "_1_all.deb",
		payload + "_1" + payload + "_all.deb",
		"ab-1" + payload + "-1.noarch.rpm",
		"ab-" + packageEntropyAPKVersion + ".apk",
		payload + "-1-1.noarch.rpm",
		payload + "-1-r0.apk",
	} {
		t.Run(filename, func(t *testing.T) {
			if _, blocked := s.pathSegmentEntropy(filename); !blocked {
				t.Fatal("fixture must block before package splitting")
			}
			remainder, version, ok := packageFilenameEntropySubjects(filename)
			if !ok {
				t.Fatal("fixture must match a package grammar")
			}
			re, rb := s.pathSegmentEntropy(remainder)
			ve, vb := s.pathSegmentEntropy(version)
			want := 0.0
			if rb || vb {
				want = math.Max(re, ve)
			}
			got, blocked := s.pathEntropy("/pool/" + filename)
			if blocked != (rb || vb) || math.Abs(got-want) > 1e-10 {
				t.Fatalf("entropy = %v, blocked = %v; want %v, %v", got, blocked, want, rb || vb)
			}
		})
	}
}

func TestPackageFilenameEntropyPreservesChecks(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	credential := "gh" + "p_" + strings.Repeat("Ab3C", 9)
	for _, tc := range []struct {
		name, raw, scanner string
	}{
		{"version credential", "https://api.vendor.example/ab_1" + credential + "_all.deb", ScannerCoreDLP},
		{"query credential", "https://api.vendor.example/" + packageEntropyDebian + "?key=" + credential, ScannerCoreDLP},
		{"private address", "https://127.0.0.1/" + packageEntropyDebian, ScannerCoreSSRF},
		{"nested payload", "https://api.vendor.example/?redirect=" + url.QueryEscape("https://assets.vendor.example/ab_1"+entropyTestMixed+"_all.deb"), ScannerEntropy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Scan(t.Context(), tc.raw)
			if got.Allowed || got.Scanner != tc.scanner {
				t.Fatalf("allowed = %v, scanner = %q, reason = %q; want %q", got.Allowed, got.Scanner, got.Reason, tc.scanner)
			}
		})
	}
}

func TestPackageFilenameEntropyOriginalScore(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	filename := "ab_1" + strings.Repeat("0", 100) + "_abcdefghijklmnopqrstuvwxyz0123456789.deb"
	if _, blocked := s.pathSegmentEntropy(filename); blocked {
		t.Fatal("whole filename must pass")
	}
	remainder, _, ok := packageFilenameEntropySubjects(filename)
	if !ok {
		t.Fatal("fixture must match")
	}
	if _, blocked := s.pathSegmentEntropy(remainder); !blocked {
		t.Fatal("split remainder must exceed the gate")
	}
	if _, blocked := s.pathEntropy("/pool/" + filename); blocked {
		t.Fatal("splitting must not introduce a block")
	}
}
