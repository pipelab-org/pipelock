// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
)

// busctl(1) --xml-interface returns the Introspect metadata without the
// property GetAll performed by its human-readable table (upstream v249
// src/busctl/busctl.c:introspect). Values still require strict typed reads.
// https://www.freedesktop.org/software/systemd/man/busctl.html#--xml-interface
func serviceCatalog(ctx context.Context, b backend) (map[string]string, error) {
	out, code, err := b.command(ctx, "/usr/bin/busctl", "--system", "--no-pager", "--xml-interface", "--allow-interactive-authorization=no", "--auto-start=no", "introspect", "org.freedesktop.systemd1", unitObject, serviceInterface)
	if err != nil || code != 0 || len(out) == 0 || len(out) > maxCatalogBytes {
		return nil, errors.New("cannot inspect service property availability")
	}
	var node struct {
		XMLName    xml.Name `xml:"node"`
		Interfaces []struct {
			Name       string `xml:"name,attr"`
			Properties []struct {
				Name   string `xml:"name,attr"`
				Type   string `xml:"type,attr"`
				Access string `xml:"access,attr"`
			} `xml:"property"`
		} `xml:"interface"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(out))
	if decoder.Decode(&node) != nil {
		return nil, errors.New("invalid service property catalog XML")
	}
	// Decode permits one root; refuse another root or trailing non-whitespace.
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("invalid trailing service catalog XML")
		}
		switch value := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(value)) == 0 {
				continue
			}
		case xml.Comment:
			continue
		}
		return nil, errors.New("unexpected trailing service catalog XML")
	}
	var properties map[string]string
	for _, iface := range node.Interfaces {
		if iface.Name != serviceInterface {
			continue
		}
		if properties != nil {
			return nil, errors.New("duplicate service catalog interface")
		}
		properties = make(map[string]string)
		for _, property := range iface.Properties {
			if !validName(property.Name) || property.Type == "" || property.Access != "read" && property.Access != "readwrite" {
				return nil, errors.New("invalid service catalog property")
			}
			if _, duplicate := properties[property.Name]; duplicate {
				return nil, errors.New("duplicate service catalog property")
			}
			properties[property.Name] = property.Type
		}
	}
	if properties == nil {
		return nil, errors.New("missing service catalog interface")
	}
	return properties, nil
}

func managerVersion(ctx context.Context, b backend) (int, []byte, error) {
	raw, err := readProperty(ctx, b, "/org/freedesktop/systemd1", managerInterface, "Version")
	if err != nil {
		return 0, nil, err
	}
	var value string
	if decodeProperty(raw, "s", &value) != nil {
		return 0, nil, errors.New("invalid system manager version")
	}
	// Join containment's detectSystemdVersion contract: the leading decimal
	// major of PID 1's version, never the installed helper's --version.
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	version, err := strconv.Atoi(value[:end])
	if err != nil || version <= 0 {
		return 0, nil, errors.New("unresolved system manager version")
	}
	return version, raw, nil
}

// Published introductions: systemd.exec(5) v255 SetLoginEnvironment (255),
// ImportCredential (254); upstream dbus-execute.c v249/v250 distinguishes
// encrypted credentials. Missing baseline properties are never synthesized.
func propertyIntroduction(name string) int {
	switch name {
	case "SetLoginEnvironment":
		return 255
	case "ImportCredential":
		return 254
	case "LoadCredentialEncrypted", "SetCredentialEncrypted":
		return 250
	default:
		return 0
	}
}
