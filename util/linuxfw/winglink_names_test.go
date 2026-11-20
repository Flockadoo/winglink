// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"
)

// Winglink's firewall names start with wl- (docs/naming.md in internal-docs).
// Tailscale's start with ts- and may be on the same machine, so anything of
// ours under another name either collides with Tailscale or is a name left
// from before the rename.
const winglinkPrefix = "wl-"

var builtinTargets = []string{"ACCEPT", "DROP", "RETURN", "REJECT", "MARK", "CONNMARK", "MASQUERADE", "SNAT", "DNAT", "TCPMSS", "LOG"}

// isBuiltinChain reports whether chain is one of the kernel's (INPUT,
// FORWARD, POSTROUTING and the rest), which are upper case.
func isBuiltinChain(chain string) bool {
	return chain != "" && chain == strings.ToUpper(chain)
}

// jumpTarget is the -j argument of an iptables rule, or "".
func jumpTarget(rule string) string {
	f := strings.Fields(rule)
	for i, w := range f {
		if w == "-j" && i+1 < len(f) {
			return f[i+1]
		}
	}
	return ""
}

func TestWinglinkIPTablesNames(t *testing.T) {
	r := newFakeIPTablesRunner()
	addr := netip.MustParseAddr("198.18.0.1")
	steps := []struct {
		name string
		f    func() error
	}{
		{"AddChains", r.AddChains},
		{"AddHooks", r.AddHooks},
		{"AddBase", func() error { return r.AddBase("winglink0") }},
		{"AddSNATRule", r.AddSNATRule},
		// Not AddStatefulRule: it finds its place by the "-A chain" form of
		// a rule, which the fake's List does not give. It adds only a DROP
		// in the forward chain.
		{"AddConnmarkSaveRule", r.AddConnmarkSaveRule},
		{"AddLoopbackRule", func() error { return r.AddLoopbackRule(addr) }},
		{"AddMagicsockPortRule", func() error { return r.AddMagicsockPortRule(41642, "udp4") }},
		{"AddExternalCGNATRules", func() error { return r.AddExternalCGNATRules(CGNATModeDrop, "winglink0") }},
		{"ClampMSSToPMTU", func() error { return r.ClampMSSToPMTU("winglink0", addr) }},
	}
	for _, s := range steps {
		if err := s.f(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
	}

	for _, ipt := range []iptablesInterface{r.ipt4, r.ipt6} {
		fake := ipt.(*fakeIPTables)
		var ours []string
		for key, rules := range fake.n {
			_, chain, _ := strings.Cut(key, "/")
			if !isBuiltinChain(chain) {
				ours = append(ours, key)
				if !strings.HasPrefix(chain, winglinkPrefix) {
					t.Errorf("chain %s is not named %s…", key, winglinkPrefix)
				}
			}
			for _, rule := range rules {
				target := jumpTarget(rule)
				if target == "" || slices.Contains(builtinTargets, target) {
					continue
				}
				if !strings.HasPrefix(target, winglinkPrefix) {
					t.Errorf("%s: rule %q jumps to %s, not to a %s… chain", key, rule, target, winglinkPrefix)
				}
			}
		}
		// The check above passes on a fake with nothing in it, so the chains
		// must also be there.
		for _, want := range []string{"filter/wl-input", "filter/wl-forward", "nat/wl-postrouting", "mangle/wl-prerouting", "mangle/wl-output"} {
			if !slices.Contains(ours, want) {
				t.Errorf("no %s; the runner made %v", want, ours)
			}
		}
	}
}

// The nftables runner checks the type, hook and priority of an existing chain
// only when it recognises the chain as its own, by its prefix. Tailscale's
// chains on the same machine are not its own.
func TestWinglinkChainsAreRecognised(t *testing.T) {
	for _, name := range []string{"wl-forward", "wl-input", "wl-postrouting", "wl-clamp"} {
		if !isTSChain(name) {
			t.Errorf("isTSChain(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"ts-forward", "ts-input", "FORWARD"} {
		if isTSChain(name) {
			t.Errorf("isTSChain(%q) = true, want false", name)
		}
	}
}

// TestWinglinkNFTablesNames needs root, for a network namespace of its own.
// CI runs it as root (.github/workflows/test.yml).
func TestWinglinkNFTablesNames(t *testing.T) {
	conn := newSysConn(t)
	r := newFakeNftablesRunnerWithConn(t, conn, true)
	addr := netip.MustParseAddr("198.18.0.1")
	steps := []struct {
		name string
		f    func() error
	}{
		{"AddChains", r.AddChains},
		{"AddHooks", r.AddHooks},
		{"AddBase", func() error { return r.AddBase("winglink0") }},
		{"AddSNATRule", r.AddSNATRule},
		{"AddConnmarkSaveRule", r.AddConnmarkSaveRule},
		{"ClampMSSToPMTU", func() error { return r.ClampMSSToPMTU("winglink0", addr) }},
	}
	for _, s := range steps {
		if err := s.f(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
	}

	var ours, tags []string
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		tables, err := conn.ListTablesOfFamily(fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, tb := range tables {
			// The tables are the usual ones (filter, nat, mangle); Winglink's
			// own are named wl-.
			if !slices.Contains([]string{"filter", "nat", "mangle"}, tb.Name) && !strings.HasPrefix(tb.Name, winglinkPrefix) {
				t.Errorf("table %s is not named %s…", tb.Name, winglinkPrefix)
			}
		}
		chains, err := conn.ListChainsOfTableFamily(fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range chains {
			if !isBuiltinChain(ch.Name) {
				ours = append(ours, ch.Table.Name+"/"+ch.Name)
				if !strings.HasPrefix(ch.Name, winglinkPrefix) {
					t.Errorf("chain %s/%s is not named %s…", ch.Table.Name, ch.Name, winglinkPrefix)
				}
			}
			rules, err := conn.GetRules(ch.Table, ch)
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range rules {
				// The connmark rules are found again by their tag.
				if tag := string(rule.UserData); strings.Contains(tag, "connmark") {
					tags = append(tags, tag)
					if !strings.HasPrefix(tag, winglinkPrefix) {
						t.Errorf("rule in %s/%s is tagged %q, not %s…", ch.Table.Name, ch.Name, tag, winglinkPrefix)
					}
				}
			}
		}
	}
	for _, want := range []string{"filter/wl-input", "filter/wl-forward", "nat/wl-postrouting", "filter/wl-clamp"} {
		if !slices.Contains(ours, want) {
			t.Errorf("no %s; the runner made %v", want, ours)
		}
	}
	for _, want := range []string{"wl-connmark-restore", "wl-connmark-save"} {
		if !slices.Contains(tags, want) {
			t.Errorf("no rule tagged %s; the tags are %v", want, tags)
		}
	}
}
