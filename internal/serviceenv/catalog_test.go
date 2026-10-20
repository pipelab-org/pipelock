// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestOlderManagerPropertyContracts(t *testing.T) {
	for _, version := range []string{"249 (249.11)", "252.36", "254"} {
		t.Run(version, func(t *testing.T) {
			f := newFixture(t)
			f.properties["manager:Version"] = typed("s", version)
			delete(f.properties, "SetLoginEnvironment")
			if strings.HasPrefix(version, "249") {
				delete(f.properties, "SetCredentialEncrypted")
				delete(f.properties, "LoadCredentialEncrypted")
			}
			if !strings.HasPrefix(version, "254") {
				delete(f.properties, "ImportCredential")
			}
			if err := check(t.Context(), fixtureOptions(), f.b); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(f.environment, "HOME=/var/lib/pipelock-proxy") {
				t.Fatal("older explicit User= home missing")
			}
			f.properties["User"] = typed("s", "")
			if err := check(t.Context(), fixtureOptions(), f.b); err != nil {
				t.Fatal(err)
			}
			for _, assignment := range f.environment {
				if strings.HasPrefix(assignment, "HOME=") {
					t.Fatal("older default user received synthesized HOME")
				}
			}
		})
	}
}

func TestCatalogNeverHidesPropertyFailures(t *testing.T) {
	for _, failure := range []string{"denied getter", "disconnected catalog", "malformed catalog", "duplicate catalog", "missing modern", "invalid version", "signature"} {
		t.Run(failure, func(t *testing.T) {
			f := newFixture(t)
			original := f.b.command
			switch failure {
			case "missing modern":
				delete(f.properties, "SetLoginEnvironment")
			case "invalid version":
				f.properties["manager:Version"] = typed("s", "unknown")
			case "signature":
				f.properties["SetLoginEnvironment"] = typed("s", "false")
			default:
				f.b.command = func(ctx context.Context, binary string, args ...string) ([]byte, int, error) {
					if slices.Contains(args, "introspect") {
						switch failure {
						case "disconnected catalog":
							return nil, -1, errors.New("disconnected")
						case "malformed catalog":
							return []byte("bad table"), 0, nil
						case "duplicate catalog":
							return []byte(`<node><interface name="` + serviceInterface + `"><property name="User" type="s" access="read"/><property name="User" type="s" access="read"/></interface></node>`), 0, nil
						}
					}
					if failure == "denied getter" && args[len(args)-1] == "SetLoginEnvironment" {
						return nil, 1, nil
					}
					return original(ctx, binary, args...)
				}
			}
			if check(t.Context(), fixtureOptions(), f.b) == nil || f.executions != 0 {
				t.Fatal("uncertain property observation was accepted")
			}
		})
	}
	// A vendor backport is present in introspection, so version gating cannot
	// skip its value or turn an explicit disabling setting into an old default.
	f := newFixture(t)
	f.properties["manager:Version"] = typed("s", "252")
	f.properties["SetLoginEnvironment"] = typed("b", false)
	if err := check(t.Context(), fixtureOptions(), f.b); err != nil {
		t.Fatal(err)
	}
	for _, assignment := range f.environment {
		if strings.HasPrefix(assignment, "HOME=") {
			t.Fatal("backported setting ignored")
		}
	}
}

func TestLoginHomeCleanAndAmbiguous255(t *testing.T) {
	f := newFixture(t)
	f.b.identity = func(string, string, []string) (identity, error) { return identity{Home: "/"}, nil }
	if err := check(t.Context(), fixtureOptions(), f.b); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.environment, "HOME=/") {
		t.Fatal("unenlightening home synthesized")
	}
	f = newFixture(t)
	f.properties["manager:Version"] = typed("s", "255")
	f.properties["User"] = typed("s", "")
	if check(t.Context(), fixtureOptions(), f.b) == nil {
		t.Fatal("unresolved255 tristate accepted")
	}
}

func TestCatalogMalformedMembersAndVersion(t *testing.T) {
	for _, body := range []string{`<node><interface name="` + serviceInterface + `"><property name="bad-name" type="s" access="read"/></interface></node>`, `<node><interface name="` + serviceInterface + `"><property name="User" type="s" access="invalid"/></interface></node>`, `<node></node><node/>`, `<node></node>trailing`, `<node><interface name="` + serviceInterface + `"/><interface name="` + serviceInterface + `"/></node>`, `malformed XML`} {
		f := newFixture(t)
		f.b.command = func(context.Context, string, ...string) ([]byte, int, error) { return []byte(body), 0, nil }
		if _, err := serviceCatalog(t.Context(), f.b); err == nil {
			t.Fatal("malformed catalog accepted")
		}
	}
	for _, body := range [][]byte{typed("s", "0"), typed("b", true)} {
		f := newFixture(t)
		f.properties["manager:Version"] = body
		if _, _, err := managerVersion(t.Context(), f.b); err == nil {
			t.Fatal("invalid manager version accepted")
		}
	}
	f := newFixture(t)
	delete(f.properties, "manager:Version")
	if _, _, err := managerVersion(t.Context(), f.b); err == nil {
		t.Fatal("missing manager version accepted")
	}
}

func TestCatalogMetadataXMLLargerThanPropertyBound(t *testing.T) {
	const observedSize = 106723
	body := `<node><interface name="` + serviceInterface + `"><property name="Environment" type="as" access="read"/></interface><!--`
	body += strings.Repeat("x", observedSize-len(body)-len(`--></node>`)) + `--></node>`
	f := newFixture(t)
	f.b.command = func(_ context.Context, _ string, args ...string) ([]byte, int, error) {
		if !slices.Contains(args, "--xml-interface") {
			t.Error("introspection must request metadata-only XML")
		}
		return []byte(body), 0, nil
	}
	got, err := serviceCatalog(t.Context(), f.b)
	if err != nil || got["Environment"] != "as" {
		t.Fatalf("valid %d-byte metadata rejected: %v", len(body), err)
	}
}

func TestCatalogXMLMetadataShape(t *testing.T) {
	for _, body := range []string{
		`<node><interface name="other.interface"><property name="Ignored" type="s" access="read"/></interface><interface name="` + serviceInterface + `"><method name="Ignored"/><signal name="Ignored"/><property name="User" type="s" access="read"/></interface></node><!--trailing comment-->`,
		`<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd"><node><interface name="` + serviceInterface + `"><property name="User" type="s" access="read"/></interface></node>`,
	} {
		f := newFixture(t)
		f.b.command = func(context.Context, string, ...string) ([]byte, int, error) { return []byte(body), 0, nil }
		got, err := serviceCatalog(t.Context(), f.b)
		if err != nil || got["User"] != "s" || len(got) != 1 {
			t.Fatalf("valid metadata XML rejected: %v", err)
		}
	}
	for _, body := range []string{`<node><interface name="` + serviceInterface + `"/></node><`, `<node><interface name="` + serviceInterface + `"><property name="User" access="read"/></interface></node>`, `<node><interface name="` + serviceInterface + `"><property name="User" type="s" access="read"/><property name="User" type="s" access="read"/></interface></node>`} {
		f := newFixture(t)
		f.b.command = func(context.Context, string, ...string) ([]byte, int, error) { return []byte(body), 0, nil }
		if _, err := serviceCatalog(t.Context(), f.b); err == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
}
