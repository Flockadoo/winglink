// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import "testing"

// Winglink's interface is winglink0 (docs/naming.md in internal-docs), so it
// does not clash with Tailscale's tailscale0 on the same machine.
func TestWinglinkTunName(t *testing.T) {
	if got, want := defaultTunName(), "winglink0"; got != want {
		t.Errorf("defaultTunName() = %q, want %q", got, want)
	}
}
