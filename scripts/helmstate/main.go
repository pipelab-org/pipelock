// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Check the decoded proxy state contract without adding a YAML tool dependency.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func main() {
	if err := check(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("decoded Helm proxy state checks passed")
}

func check(paths []string) error {
	for _, path := range paths {
		if err := checkFile(path); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}

func checkFile(path string) error {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	decoder := yaml.NewDecoder(f)
	deployments := 0
	for {
		var doc struct {
			Kind string `yaml:"kind"`
			Spec struct {
				Template struct {
					Spec struct {
						SecurityContext struct {
							FSGroup int `yaml:"fsGroup"`
						} `yaml:"securityContext"`
						Containers []struct {
							Args []string `yaml:"args"`
							Env  []struct {
								Name, Value string
								ValueFrom   map[string]interface{} `yaml:"valueFrom"`
							} `yaml:"env"`
							Mounts []struct {
								Name     string
								Path     string `yaml:"mountPath"`
								ReadOnly bool   `yaml:"readOnly"`
							} `yaml:"volumeMounts"`
							Security struct {
								ReadOnly     bool `yaml:"readOnlyRootFilesystem"`
								NonRoot      bool `yaml:"runAsNonRoot"`
								User         int  `yaml:"runAsUser"`
								Escalation   bool `yaml:"allowPrivilegeEscalation"`
								Capabilities struct {
									Drop []string `yaml:"drop"`
								} `yaml:"capabilities"`
							} `yaml:"securityContext"`
						} `yaml:"containers"`
						Volumes []struct {
							Name     string
							EmptyDir *map[string]interface{} `yaml:"emptyDir"`
							PVC      map[string]interface{}  `yaml:"persistentVolumeClaim"`
						} `yaml:"volumes"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if err := decoder.Decode(&doc); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		if doc.Kind != "Deployment" {
			continue
		}
		deployments++
		pod := doc.Spec.Template.Spec
		if len(pod.Containers) != 1 {
			return fmt.Errorf("expected one container")
		}
		c := pod.Containers[0]
		proxy := len(c.Args) > 0 && c.Args[0] == "run"
		custom := strings.HasPrefix(filepath.Base(path), "custom-state")
		envs, mounts, volumes := 0, 0, 0
		statePath := "/var/lib/pipelock/state"
		if custom {
			statePath = "/custom/state"
		}
		for _, env := range c.Env {
			if env.Name == "XDG_STATE_HOME" {
				envs++
				if strings.Contains(filepath.Base(path), "valuefrom") {
					if env.ValueFrom["configMapKeyRef"] == nil || env.Value != "" {
						return fmt.Errorf("state valueFrom changed")
					}
				} else if env.Value != statePath || env.ValueFrom != nil {
					return fmt.Errorf("state home changed: %+v", env)
				}
			}
		}
		for _, mount := range c.Mounts {
			if mount.Name == "pipelock-state" {
				mounts++
				if mount.Path != statePath || mount.ReadOnly {
					return fmt.Errorf("state mount not writable at state home")
				}
			}
		}
		for _, volume := range pod.Volumes {
			if volume.Name == "pipelock-state" {
				volumes++
				if custom {
					if volume.PVC["claimName"] != "existing-state" || volume.EmptyDir != nil {
						return fmt.Errorf("custom storage changed")
					}
				} else if volume.EmptyDir == nil {
					return fmt.Errorf("state emptyDir missing")
				}
			}
		}
		if !proxy {
			if envs+mounts+volumes != 0 {
				return fmt.Errorf("proxy state leaked into server mode")
			}
			continue
		}
		if envs != 1 || mounts != 1 || volumes != 1 {
			return fmt.Errorf("state links: env=%d mount=%d volume=%d", envs, mounts, volumes)
		}
		if pod.SecurityContext.FSGroup != 65534 || !c.Security.ReadOnly || !c.Security.NonRoot || c.Security.User != 65534 || c.Security.Escalation || len(c.Security.Capabilities.Drop) != 1 || c.Security.Capabilities.Drop[0] != "ALL" {
			return fmt.Errorf("proxy security settings changed")
		}
	}
	if deployments != 1 {
		return fmt.Errorf("expected one Deployment, got %d", deployments)
	}
	return nil
}
