// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package osrouter

import "testing"

// Winglink's routing table is 87, named winglink (docs/naming.md in
// internal-docs). Tailscale owns 52.
func TestWinglinkRouteTable(t *testing.T) {
	if want := (RouteTable{Name: "winglink", Num: 87}); tailscaleRouteTable != want {
		t.Errorf("route table %+v, want %+v", tailscaleRouteTable, want)
	}
}
