// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsconst

// Linux firewall marks. Inferscale uses the top byte so it does not
// overlap Tailscale, which claims 0xff0000. A shared mask makes each
// daemon match the other's packets.
const (
	LinuxFwmarkMask    = "0xff000000"
	LinuxFwmarkMaskNum = 0xff000000

	// Packet is from Inferscale and to a subnet route destination, so
	// is allowed to be routed through this machine.
	LinuxSubnetRouteMark    = "0x04000000"
	LinuxSubnetRouteMarkNum = 0x04000000

	// Packet was originated by inferscaled itself, and must not be
	// routed over the Inferscale network.
	LinuxBypassMark    = "0x08000000"
	LinuxBypassMarkNum = 0x08000000
)
