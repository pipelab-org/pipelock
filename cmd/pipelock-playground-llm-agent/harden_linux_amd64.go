// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package main

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/sandbox"
)

type hardenOps struct {
	setDumpable  func() error
	applySeccomp func() error
}

func realHardenOps() hardenOps {
	return hardenOps{
		setDumpable: func() error {
			return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
		},
		applySeccomp: func() error {
			_, err := sandbox.ApplySeccomp(false)
			return err
		},
	}
}

// hardenProcess locks down the LLM agent process before it reads the model key.
// The settings are inherited by run_command shell children: no dumpable memory,
// no setuid-style privilege gain, and no unshare/mount/device-node syscalls.
func hardenProcess() error {
	return hardenProcessWithOps(realHardenOps())
}

func hardenProcessWithOps(ops hardenOps) error {
	if err := ops.setDumpable(); err != nil {
		return fmt.Errorf("set non-dumpable: %w", err)
	}
	if err := ops.applySeccomp(); err != nil {
		return fmt.Errorf("install seccomp: %w", err)
	}
	return nil
}
