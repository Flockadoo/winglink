// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/net/tsaddr"
	"tailscale.com/tsconst"
)

var testIsNotExistErr = "exitcode:1"

func init() {
	isNotExistError = func(e error) bool { return e.Error() == testIsNotExistErr }
}

func TestAddAndDeleteChains(t *testing.T) {
	iptr := newFakeIPTablesRunner()
	err := iptr.AddChains()
	if err != nil {
		t.Fatal(err)
	}

	// Check that the chains were created.
	tsChains := []struct{ table, chain string }{ // table/chain
		{"filter", "wl-input"},
		{"filter", "wl-forward"},
		{"nat", "wl-postrouting"},
	}

	for _, proto := range []iptablesInterface{iptr.ipt4, iptr.ipt6} {
		for _, tc := range tsChains {
			// Exists returns error if the chain doesn't exist.
			if _, err := proto.Exists(tc.table, tc.chain); err != nil {
				t.Errorf("chain %s/%s doesn't exist", tc.table, tc.chain)
			}
		}
	}

	err = iptr.DelChains()
	if err != nil {
		t.Fatal(err)
	}

	// Check that the chains were deleted.
	for _, proto := range []iptablesInterface{iptr.ipt4, iptr.ipt6} {
		for _, tc := range tsChains {
			if _, err = proto.Exists(tc.table, tc.chain); err == nil {
				t.Errorf("chain %s/%s still exists", tc.table, tc.chain)
			}
		}
	}

}

func TestAddAndDeleteHooks(t *testing.T) {
	iptr := newFakeIPTablesRunner()
	// don't need to test what happens if the chains don't exist, because
	// this is handled by fake iptables, in realife iptables would return error.
	if err := iptr.AddChains(); err != nil {
		t.Fatal(err)
	}
	defer iptr.DelChains()

	if err := iptr.AddHooks(); err != nil {
		t.Fatal(err)
	}

	// Check that the rules were created.
	tsRules := []fakeRule{ // table/chain/rule
		{"filter", "INPUT", []string{"-j", "wl-input"}},
		{"filter", "FORWARD", []string{"-j", "wl-forward"}},
		{"nat", "POSTROUTING", []string{"-j", "wl-postrouting"}},
	}

	for _, proto := range []iptablesInterface{iptr.ipt4, iptr.ipt6} {
		for _, tr := range tsRules {
			if exists, err := proto.Exists(tr.table, tr.chain, tr.args...); err != nil {
				t.Fatal(err)
			} else if !exists {
				t.Errorf("rule %s/%s/%s doesn't exist", tr.table, tr.chain, strings.Join(tr.args, " "))
			}
			// check if the rule is at front of the chain
			if proto.(*fakeIPTables).n[tr.table+"/"+tr.chain][0] != strings.Join(tr.args, " ") {
				t.Errorf("v4 rule %s/%s/%s is not at the top", tr.table, tr.chain, strings.Join(tr.args, " "))
			}
		}
	}

	if err := iptr.DelHooks(t.Logf); err != nil {
		t.Fatal(err)
	}

	// Check that the rules were deleted.
	for _, proto := range []iptablesInterface{iptr.ipt4, iptr.ipt6} {
		for _, tr := range tsRules {
			if exists, err := proto.Exists(tr.table, tr.chain, tr.args...); err != nil {
				t.Fatal(err)
			} else if exists {
				t.Errorf("rule %s/%s/%s still exists", tr.table, tr.chain, strings.Join(tr.args, " "))
			}
		}
	}

	if err := iptr.AddHooks(); err != nil {
		t.Fatal(err)
	}
}

func TestAddAndDeleteBase(t *testing.T) {
	iptr := newFakeIPTablesRunner()
	tunname := "tun0"
	if err := iptr.AddChains(); err != nil {
		t.Fatal(err)
	}

	if err := iptr.AddBase(tunname); err != nil {
		t.Fatal(err)
	}

	// Check that the rules were created.
	tsRulesV4 := []fakeRule{ // table/chain/rule
		{"filter", "wl-forward", []string{"-o", tunname, "-s", tsaddr.CGNATRange().String(), "-j", "DROP"}},
	}

	tsRulesCommon := []fakeRule{ // table/chain/rule
		{"filter", "wl-input", []string{"-i", tunname, "-j", "ACCEPT"}},
		{"filter", "wl-forward", []string{"-i", tunname, "-j", "MARK", "--set-mark", tsconst.LinuxSubnetRouteMark + "/" + tsconst.LinuxFwmarkMask}},
		{"filter", "wl-forward", []string{"-m", "mark", "--mark", tsconst.LinuxSubnetRouteMark + "/" + tsconst.LinuxFwmarkMask, "-j", "ACCEPT"}},
		{"filter", "wl-forward", []string{"-o", tunname, "-j", "ACCEPT"}},
	}

	// check that the rules were created for ipt4
	for _, tr := range append(tsRulesV4, tsRulesCommon...) {
		if exists, err := iptr.ipt4.Exists(tr.table, tr.chain, tr.args...); err != nil {
			t.Fatal(err)
		} else if !exists {
			t.Errorf("rule %s/%s/%s doesn't exist", tr.table, tr.chain, strings.Join(tr.args, " "))
		}
	}

	// check that the rules were created for ipt6
	for _, tr := range tsRulesCommon {
		if exists, err := iptr.ipt6.Exists(tr.table, tr.chain, tr.args...); err != nil {
			t.Fatal(err)
		} else if !exists {
			t.Errorf("rule %s/%s/%s doesn't exist", tr.table, tr.chain, strings.Join(tr.args, " "))
		}
	}

	if err := iptr.DelBase(); err != nil {
		t.Fatal(err)
	}

	// Check that the rules were deleted.
	for _, proto := range []iptablesInterface{iptr.ipt4, iptr.ipt6} {
		for _, tr := range append(tsRulesV4, tsRulesCommon...) {
			if exists, err := proto.Exists(tr.table, tr.chain, tr.args...); err != nil {
				t.Fatal(err)
			} else if exists {
				t.Errorf("rule %s/%s/%s still exists", tr.table, tr.chain, strings.Join(tr.args, " "))
			}
		}
	}

	if err := iptr.DelChains(); err != nil {
		t.Fatal(err)
	}
}

func TestAddAndDelLoopbackRule(t *testing.T) {
	iptr := newFakeIPTablesRunner()
	// We don't need to test for malformed addresses, AddLoopbackRule
	// takes in a netip.Addr, which is already valid.
	fakeAddrV4 := netip.MustParseAddr("192.168.0.2")
	fakeAddrV6 := netip.MustParseAddr("2001:db8::2")

	if err := iptr.AddChains(); err != nil {
		t.Fatal(err)
	}
	if err := iptr.AddLoopbackRule(fakeAddrV4); err != nil {
		t.Fatal(err)
	}
	if err := iptr.AddLoopbackRule(fakeAddrV6); err != nil {
		t.Fatal(err)
	}

	// Check that the rules were created.
	tsRulesV4 := fakeRule{ // table/chain/rule
		"filter", "wl-input", []string{"-i", "lo", "-s", fakeAddrV4.String(), "-j", "ACCEPT"}}

	tsRulesV6 := fakeRule{ // table/chain/rule
		"filter", "wl-input", []string{"-i", "lo", "-s", fakeAddrV6.String(), "-j", "ACCEPT"}}

	// check that the rules were created for ipt4 and ipt6
	if exist, err := iptr.ipt4.Exists(tsRulesV4.table, tsRulesV4.chain, tsRulesV4.args...); err != nil {
		t.Fatal(err)
	} else if !exist {
		t.Errorf("rule %s/%s/%s doesn't exist", tsRulesV4.table, tsRulesV4.chain, strings.Join(tsRulesV4.args, " "))
	}
	if exist, err := iptr.ipt6.Exists(tsRulesV6.table, tsRulesV6.chain, tsRulesV6.args...); err != nil {
		t.Fatal(err)
	} else if !exist {
		t.Errorf("rule %s/%s/%s doesn't exist", tsRulesV6.table, tsRulesV6.chain, strings.Join(tsRulesV6.args, " "))
	}

	// check that the rule is at the top
	chain := "filter/wl-input"
	if iptr.ipt4.(*fakeIPTables).n[chain][0] != strings.Join(tsRulesV4.args, " ") {
		t.Errorf("v4 rule %s/%s/%s is not at the top", tsRulesV4.table, tsRulesV4.chain, strings.Join(tsRulesV4.args, " "))
	}
	if iptr.ipt6.(*fakeIPTables).n[chain][0] != strings.Join(tsRulesV6.args, " ") {
		t.Errorf("v6 rule %s/%s/%s is not at the top", tsRulesV6.table, tsRulesV6.chain, strings.Join(tsRulesV6.args, " "))
	}

	// delete the rules
	if err := iptr.DelLoopbackRule(fakeAddrV4); err != nil {
		t.Fatal(err)
	}
	if err := iptr.DelLoopbackRule(fakeAddrV6); err != nil {
		t.Fatal(err)
	}

	// Check that the rules were deleted.
	if exist, err := iptr.ipt4.Exists(tsRulesV4.table, tsRulesV4.chain, tsRulesV4.args...); err != nil {
		t.Fatal(err)
	} else if exist {
		t.Errorf("rule %s/%s/%s still exists", tsRulesV4.table, tsRulesV4.chain, strings.Join(tsRulesV4.args, " "))
	}

	if exist, err := iptr.ipt6.Exists(tsRulesV6.table, tsRulesV6.chain, tsRulesV6.args...); err != nil {
		t.Fatal(err)
	} else if exist {
		t.Errorf("rule %s/%s/%s still exists", tsRulesV6.table, tsRulesV6.chain, strings.Join(tsRulesV6.args, " "))
	}

	if err := iptr.DelChains(); err != nil {
		t.Fatal(err)
	}
}

func TestAddAndDelSNATRule(t *testing.T) {
	iptr := newFakeIPTablesRunner()

	if err := iptr.AddChains(); err != nil {
		t.Fatal(err)
	}

	rule := fakeRule{ // table/chain/rule
		"nat", "wl-postrouting", []string{"-m", "mark", "--mark", tsconst.LinuxSubnetRouteMark + "/" + tsconst.LinuxFwmarkMask, "-j", "MASQUERADE"},
	}

	// Add SNAT rule
	if err := iptr.AddSNATRule(); err != nil {
		t.Fatal(err)
	}

	// Check that the rule was created for ipt4 and ipt6
	for _, proto := range []iptablesInterface{iptr.ipt4, iptr.ipt6} {
		if exist, err := proto.Exists(rule.table, rule.chain, rule.args...); err != nil {
			t.Fatal(err)
		} else if !exist {
			t.Errorf("rule %s/%s/%s doesn't exist", rule.table, rule.chain, strings.Join(rule.args, " "))
		}
	}

	// Delete SNAT rule
	if err := iptr.DelSNATRule(); err != nil {
		t.Fatal(err)
	}

	// Check that the rule was deleted for ipt4 and ipt6
	for _, proto := range []iptablesInterface{iptr.ipt4, iptr.ipt6} {
		if exist, err := proto.Exists(rule.table, rule.chain, rule.args...); err != nil {
			t.Fatal(err)
		} else if exist {
			t.Errorf("rule %s/%s/%s still exists", rule.table, rule.chain, strings.Join(rule.args, " "))
		}
	}

	if err := iptr.DelChains(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureSNATForDst_ipt(t *testing.T) {
	ip1, ip2, ip3 := netip.MustParseAddr("100.99.99.99"), netip.MustParseAddr("100.88.88.88"), netip.MustParseAddr("100.77.77.77")
	iptr := newFakeIPTablesRunner()

	// 1. A new rule gets added
	mustCreateSNATRule_ipt(t, iptr, ip1, ip2)
	checkSNATRule_ipt(t, iptr, ip1, ip2)
	checkSNATRuleCount(t, iptr, ip1, 1)

	// 2. Another call to EnsureSNATForDst with the same src and dst does not result in another rule being added.
	mustCreateSNATRule_ipt(t, iptr, ip1, ip2)
	checkSNATRule_ipt(t, iptr, ip1, ip2)
	checkSNATRuleCount(t, iptr, ip1, 1) // still just 1 rule

	// 3. Another call to EnsureSNATForDst with a different src and the same dst results in the earlier rule being
	// deleted.
	mustCreateSNATRule_ipt(t, iptr, ip3, ip2)
	checkSNATRule_ipt(t, iptr, ip3, ip2)
	checkSNATRuleCount(t, iptr, ip1, 1) // still just 1 rule

	// 4. Another call to EnsureSNATForDst with a different dst should not get the earlier rule deleted.
	mustCreateSNATRule_ipt(t, iptr, ip3, ip1)
	checkSNATRule_ipt(t, iptr, ip3, ip1)
	checkSNATRuleCount(t, iptr, ip1, 2) // now 2 rules

	// 5. A call to EnsureSNATForDst with a match dst and a match port should not get deleted by EnsureSNATForDst for the same dst.
	args := []string{"--destination", ip1.String(), "-j", "SNAT", "--to-source", "10.0.0.1"}
	if err := iptr.getIPTByAddr(ip1).Insert("nat", "POSTROUTING", 1, args...); err != nil {
		t.Fatalf("error adding SNAT rule: %v", err)
	}
	exists, err := iptr.getIPTByAddr(ip1).Exists("nat", "POSTROUTING", args...)
	if err != nil {
		t.Fatalf("error checking if rule exists: %v", err)
	}
	if !exists {
		t.Fatalf("SNAT rule for destination and port unexpectedly deleted")
	}
	mustCreateSNATRule_ipt(t, iptr, ip3, ip1)
	checkSNATRuleCount(t, iptr, ip1, 3) // now 3 rules
}

func mustCreateSNATRule_ipt(t *testing.T, iptr *iptablesRunner, src, dst netip.Addr) {
	t.Helper()
	if err := iptr.EnsureSNATForDst(src, dst); err != nil {
		t.Fatalf("error ensuring SNAT rule: %v", err)
	}
}

func checkSNATRule_ipt(t *testing.T, iptr *iptablesRunner, src, dst netip.Addr) {
	t.Helper()
	dstPrefix, err := dst.Prefix(32)
	if err != nil {
		t.Fatalf("error converting addr to prefix: %v", err)
	}
	exists, err := iptr.getIPTByAddr(src).Exists("nat", "POSTROUTING", "-d", dstPrefix.String(), "-j", "SNAT", "--to-source", src.String())
	if err != nil {
		t.Fatalf("error checking if rule exists: %v", err)
	}
	if !exists {
		t.Fatalf("SNAT rule for src %s dst %s should exist, but it does not", src, dst)
	}
}

func checkSNATRuleCount(t *testing.T, iptr *iptablesRunner, ip netip.Addr, wantsRules int) {
	t.Helper()
	rules, err := iptr.getIPTByAddr(ip).List("nat", "POSTROUTING")
	if err != nil {
		t.Fatalf("error listing rules: %v", err)
	}
	if len(rules) != wantsRules {
		t.Fatalf("wants %d rules, got %d", wantsRules, len(rules))
	}
}

// tailscaleSeesItsConnmarkRule is Tailscale's own check, copied from
// AddConnmarkSaveRule in tailscale.com/util/linuxfw/iptables_runner.go
// (upstream main, November 2026). When it is true, tailscaled concludes its
// connmark rules are installed and adds none.
func tailscaleSeesItsConnmarkRule(t *testing.T, ipt iptablesInterface) bool {
	t.Helper()
	rules, err := ipt.List("mangle", "PREROUTING")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if strings.Contains(rule, "CONNMARK") &&
			strings.Contains(rule, "restore-mark") &&
			strings.Contains(rule, "ctmask 0xff0000") {
			return true
		}
	}
	return false
}

// Winglink's two connmark rules live in chains of its own in the mangle
// table, wl-prerouting and wl-output, each reached by one jump at the top of
// the built-in chain. Nothing else of Winglink's is in the built-in
// chains. Tailscale searches the listing of mangle/PREROUTING for the text
// "ctmask 0xff0000" to decide whether its own rules are installed, and the
// text of Winglink's mask, 0xff000000, begins with Tailscale's: a rule of
// ours in that chain made Tailscale skip its own.
func TestAddAndDelConnmarkSaveRule(t *testing.T) {
	type placed struct {
		builtin, chain string
		args           []string
	}
	rules := []placed{
		{"PREROUTING", "wl-prerouting", []string{
			"-m", "conntrack",
			"--ctstate", "ESTABLISHED,RELATED",
			"-m", "connmark",
			"!", "--mark", "0x0/0xff000000",
			"-j", "CONNMARK",
			"--restore-mark",
			"--nfmask", "0xff000000",
			"--ctmask", "0xff000000",
		}},
		{"OUTPUT", "wl-output", []string{
			"-m", "conntrack",
			"--ctstate", "NEW",
			"-m", "mark",
			"!", "--mark", "0x0/0xff000000",
			"-j", "CONNMARK",
			"--save-mark",
			"--nfmask", "0xff000000",
			"--ctmask", "0xff000000",
		}},
	}
	// tailscale is the same rule as Tailscale installs it, with its mask.
	tailscale := func(args []string) []string {
		out := make([]string, len(args))
		for i, a := range args {
			out[i] = strings.ReplaceAll(a, "0xff000000", "0xff0000")
		}
		return out
	}
	// list is the rules of mangle/chain; ok is false if there is no such chain.
	list := func(ipt iptablesInterface, chain string) (rules []string, ok bool) {
		rules, err := ipt.List("mangle", chain)
		return rules, err == nil
	}
	count := func(ipt iptablesInterface, chain string, args []string) int {
		rules, _ := list(ipt, chain)
		n := 0
		for _, rule := range rules {
			if rule == strings.Join(args, " ") {
				n++
			}
		}
		return n
	}
	wantInstalled := func(t *testing.T, name string, ipt iptablesInterface) {
		t.Helper()
		for _, r := range rules {
			if got, _ := list(ipt, r.chain); len(got) != 1 || got[0] != strings.Join(r.args, " ") {
				t.Errorf("%s: mangle/%s = %q, want only the connmark rule", name, r.chain, got)
			}
			if n := count(ipt, r.builtin, []string{"-j", r.chain}); n != 1 {
				t.Errorf("%s: %d jumps to %s in mangle/%s, want 1", name, n, r.chain, r.builtin)
			}
			if n := count(ipt, r.builtin, r.args); n != 0 {
				t.Errorf("%s: the connmark rule is in the built-in mangle/%s", name, r.builtin)
			}
		}
		if tailscaleSeesItsConnmarkRule(t, ipt) {
			t.Errorf("%s: Tailscale takes a rule in mangle/PREROUTING for its own and will not add its connmark rules", name)
		}
	}
	wantRemoved := func(t *testing.T, name string, ipt iptablesInterface) {
		t.Helper()
		for _, r := range rules {
			if _, ok := list(ipt, r.chain); ok {
				t.Errorf("%s: mangle/%s still exists", name, r.chain)
			}
			if count(ipt, r.builtin, []string{"-j", r.chain}) != 0 || count(ipt, r.builtin, r.args) != 0 {
				t.Errorf("%s: something of Winglink's is left in mangle/%s", name, r.builtin)
			}
		}
	}
	both := func(iptr *iptablesRunner) map[string]iptablesInterface {
		return map[string]iptablesInterface{"IPv4": iptr.ipt4, "IPv6": iptr.ipt6}
	}

	t.Run("with_ipv6", func(t *testing.T) {
		iptr := newFakeIPTablesRunner()
		for call := 1; call <= 2; call++ { // the second call changes nothing
			if err := iptr.AddConnmarkSaveRule(); err != nil {
				t.Fatalf("AddConnmarkSaveRule (call %d) failed: %v", call, err)
			}
			for name, ipt := range both(iptr) {
				wantInstalled(t, name, ipt)
				for _, r := range rules {
					if got, _ := list(ipt, r.builtin); len(got) == 0 || got[0] != "-j "+r.chain {
						t.Errorf("%s: the jump is not first in mangle/%s: %q", name, r.builtin, got)
					}
				}
			}
		}
		for call := 1; call <= 2; call++ { // deleting twice is not an error
			if err := iptr.DelConnmarkSaveRule(); err != nil {
				t.Fatalf("DelConnmarkSaveRule (call %d) failed: %v", call, err)
			}
			for name, ipt := range both(iptr) {
				wantRemoved(t, name, ipt)
			}
		}
	})

	t.Run("without_ipv6", func(t *testing.T) {
		// A system without IPv6: ipt6 is nil and must not be touched.
		iptr := &iptablesRunner{ipt4: newFakeIPTables()}
		if err := iptr.AddConnmarkSaveRule(); err != nil {
			t.Fatalf("AddConnmarkSaveRule failed with IPv6 disabled: %v", err)
		}
		wantInstalled(t, "IPv4", iptr.ipt4)
		if err := iptr.DelConnmarkSaveRule(); err != nil {
			t.Fatalf("DelConnmarkSaveRule failed with IPv6 disabled: %v", err)
		}
		wantRemoved(t, "IPv4", iptr.ipt4)
	})

	// Tailscale installed its rules first. They are not ours: ours are still
	// added, once, and Tailscale's are left alone.
	t.Run("after_tailscale", func(t *testing.T) {
		iptr := newFakeIPTablesRunner()
		for _, ipt := range both(iptr) {
			for _, r := range rules {
				if err := ipt.Insert("mangle", r.builtin, 1, tailscale(r.args)...); err != nil {
					t.Fatal(err)
				}
			}
		}
		for call := 1; call <= 2; call++ {
			if err := iptr.AddConnmarkSaveRule(); err != nil {
				t.Fatalf("AddConnmarkSaveRule (call %d) failed: %v", call, err)
			}
			for name, ipt := range both(iptr) {
				for _, r := range rules {
					if got, _ := list(ipt, r.chain); len(got) != 1 || got[0] != strings.Join(r.args, " ") {
						t.Errorf("call %d, %s: mangle/%s = %q, want only the connmark rule", call, name, r.chain, got)
					}
					if n := count(ipt, r.builtin, []string{"-j", r.chain}); n != 1 {
						t.Errorf("call %d, %s: %d jumps to %s, want 1", call, name, n, r.chain)
					}
					if n := count(ipt, r.builtin, tailscale(r.args)); n != 1 {
						t.Errorf("call %d, %s: %d of Tailscale's rules in mangle/%s, want 1 untouched", call, name, n, r.builtin)
					}
				}
			}
		}
	})

	// Tailscale starts after Winglink. Its own check must not take anything
	// of ours for its rule, so it adds its two rules, and ours stay.
	t.Run("before_tailscale", func(t *testing.T) {
		iptr := newFakeIPTablesRunner()
		if err := iptr.AddConnmarkSaveRule(); err != nil {
			t.Fatal(err)
		}
		for name, ipt := range both(iptr) {
			if tailscaleSeesItsConnmarkRule(t, ipt) {
				t.Fatalf("%s: Tailscale takes a rule in mangle/PREROUTING for its own and will not add its connmark rules", name)
			}
			// What tailscaled does next, having found none of its rules.
			for _, r := range rules {
				if err := ipt.Insert("mangle", r.builtin, 1, tailscale(r.args)...); err != nil {
					t.Fatal(err)
				}
			}
			for _, r := range rules {
				if got, _ := list(ipt, r.chain); len(got) != 1 || got[0] != strings.Join(r.args, " ") {
					t.Errorf("%s: mangle/%s = %q after Tailscale started, want only the connmark rule", name, r.chain, got)
				}
				if count(ipt, r.builtin, []string{"-j", r.chain}) != 1 {
					t.Errorf("%s: the jump to %s is gone after Tailscale started", name, r.chain)
				}
			}
		}
	})

	// Whatever is missing is put back, and what is there is not doubled: a
	// jump or a rule can be lost (a call that failed half way, a flush by an
	// administrator), in one table and not the other.
	t.Run("restores_what_is_missing", func(t *testing.T) {
		for _, r := range rules {
			for _, lose := range []struct {
				what string
				do   func(ipt iptablesInterface) error
			}{
				{"the jump from " + r.builtin, func(ipt iptablesInterface) error { return ipt.Delete("mangle", r.builtin, "-j", r.chain) }},
				{"the rule in " + r.chain, func(ipt iptablesInterface) error { return ipt.ClearChain("mangle", r.chain) }},
			} {
				iptr := newFakeIPTablesRunner()
				if err := iptr.AddConnmarkSaveRule(); err != nil {
					t.Fatal(err)
				}
				if err := lose.do(iptr.ipt4); err != nil {
					t.Fatalf("losing %s: %v", lose.what, err)
				}
				if err := iptr.AddConnmarkSaveRule(); err != nil {
					t.Fatalf("AddConnmarkSaveRule after losing %s: %v", lose.what, err)
				}
				for name, ipt := range both(iptr) {
					wantInstalled(t, name+" after losing "+lose.what, ipt)
				}
			}
		}
	})

	// A build from before the rules had chains of their own left them in the
	// built-in chains. Adding moves them; deleting removes them too.
	t.Run("replaces_rules_from_an_older_build", func(t *testing.T) {
		older := func() *iptablesRunner {
			iptr := newFakeIPTablesRunner()
			for _, ipt := range both(iptr) {
				for _, r := range rules {
					if err := ipt.Insert("mangle", r.builtin, 1, r.args...); err != nil {
						t.Fatal(err)
					}
				}
			}
			return iptr
		}
		iptr := older()
		if err := iptr.AddConnmarkSaveRule(); err != nil {
			t.Fatal(err)
		}
		for name, ipt := range both(iptr) {
			wantInstalled(t, name, ipt)
		}
		iptr = older()
		if err := iptr.DelConnmarkSaveRule(); err != nil {
			t.Fatal(err)
		}
		for name, ipt := range both(iptr) {
			wantRemoved(t, name, ipt)
		}
	})
}

func TestAddAndDelCGNATRules(t *testing.T) {
	iptr := newFakeIPTablesRunner()
	tunname := "tun0"

	// We need the chains to exist so we can add rules into them.
	if err := iptr.AddChains(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		mode      CGNATMode
		wantRules []fakeRule
	}{
		{
			CGNATModeDrop, []fakeRule{
				{"filter", "wl-input", []string{"!", "-i", tunname, "-s", tsaddr.ChromeOSVMRange().String(), "-j", "RETURN"}},
				{"filter", "wl-input", []string{"!", "-i", tunname, "-s", tsaddr.CGNATRange().String(), "-j", "DROP"}},
			},
		},
		{
			CGNATModeReturn, []fakeRule{
				{"filter", "wl-input", []string{"!", "-i", tunname, "-s", tsaddr.CGNATRange().String(), "-j", "RETURN"}},
			},
		},
	}

	for _, tt := range tests {
		if err := iptr.AddExternalCGNATRules(tt.mode, tunname); err != nil {
			t.Fatal(err)
		}

		for _, tr := range tt.wantRules {
			if exists, err := iptr.ipt4.Exists(tr.table, tr.chain, tr.args...); err != nil {
				t.Fatalf("mode %q: error checking for rule: %v", tt.mode, err)
			} else if !exists {
				t.Errorf("mode %q: rule %s/%s/%s doesn't exist", tt.mode, tr.table, tr.chain, strings.Join(tr.args, " "))
			}
		}

		if err := iptr.DelExternalCGNATRules(tt.mode, tunname); err != nil {
			t.Fatal(err)
		}

		for _, tr := range tt.wantRules {
			if exists, err := iptr.ipt4.Exists(tr.table, tr.chain, tr.args...); err != nil {
				t.Fatalf("mode %q: error checking for rule: %v", tt.mode, err)
			} else if exists {
				t.Errorf("mode %q: rule %s/%s/%s not deleted", tt.mode, tr.table, tr.chain, strings.Join(tr.args, " "))
			}
		}
	}
}

// TestDelLoopbackRuleMissing verifies DelLoopbackRule is a no-op (not an error)
// when the rule is absent, so removing an address whose loopback rule was never
// added in this instance -- e.g. one left on the interface by a previous
// tailscaled -- isn't blocked. See tailscale/tailscale#19974.
func TestDelLoopbackRuleMissing(t *testing.T) {
	iptr := newFakeIPTablesRunner()
	if err := iptr.AddChains(); err != nil {
		t.Fatal(err)
	}
	defer iptr.DelChains()

	addr := netip.MustParseAddr("100.64.0.99")
	rule := []string{"-i", "lo", "-s", addr.String(), "-j", "ACCEPT"}

	// No AddLoopbackRule for addr, so its rule is absent. Delete must not error.
	if err := iptr.DelLoopbackRule(addr); err != nil {
		t.Fatalf("DelLoopbackRule with no rule present: %v", err)
	}

	// And it still deletes the rule when present.
	if err := iptr.AddLoopbackRule(addr); err != nil {
		t.Fatal(err)
	}
	if err := iptr.DelLoopbackRule(addr); err != nil {
		t.Fatalf("DelLoopbackRule with rule present: %v", err)
	}
	if exists, err := iptr.ipt4.Exists("filter", "wl-input", rule...); err != nil {
		t.Fatal(err)
	} else if exists {
		t.Error("loopback rule still present after DelLoopbackRule")
	}
}
