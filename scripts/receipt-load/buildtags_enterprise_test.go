// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

//go:build enterprise

package main

// realBuildTags makes the real child match this test binary's edition, so the
// enterprise run exercises enterprise-only runtime behavior too.
const realBuildTags = "enterprise"
