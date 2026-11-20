// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package paths

import (
	"os"
	"path/filepath"
	"testing"
)

// The names Winglink uses on disk (docs/naming.md in internal-docs). The
// Flockadoo client finds the daemon by its socket.
func TestWinglinkPaths(t *testing.T) {
	if got, want := statePath(), "/var/lib/winglink/winglinkd.state"; got != want {
		t.Errorf("statePath() = %q, want %q", got, want)
	}
	if got, want := DefaultTailscaledSocket(), "/var/run/winglink/winglinkd.sock"; got != want {
		t.Errorf("DefaultTailscaledSocket() = %q, want %q", got, want)
	}
}

// Winglink's state directory is made private, as upstream makes Tailscale's;
// a directory of another name is left alone.
func TestWinglinkStateDirIsPrivate(t *testing.T) {
	for name, want := range map[string]os.FileMode{"winglink": 0o700, "other": 0o755} {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// Mkdir applies the umask.
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := ensureStateDirPermsUnix(dir); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", name, got, want)
		}
	}
}
