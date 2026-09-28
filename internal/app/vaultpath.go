package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// The sources a vault path can come from, as the banner reports them. The first
// two are config's own labels, so the banner and the flag help cannot drift.
const (
	sourceFlag       = "flag:--vault"
	sourceDefault    = "default: next to the executable"
	sourceDataDir    = "data directory: the executable's directory is not writable"
	sourceConfigured = "configured"
)

// vaultChoice is where the vault is and why.
type vaultChoice struct {
	// Root is the absolute vault root.
	Root string
	// Source is how the path was chosen, for the banner.
	Source string
	// Warnings are the facts the operator should know about the choice. A
	// fallback is a warning and not a note: a vault in a directory nobody
	// expected is a vault that gets backed up to the wrong place.
	Warnings []string
}

// chooseVault resolves the vault root, in the plan's order: the flag, then the
// environment, then <exe dir>/vault, and only then the platform data directory.
//
// The writability of a candidate is decided by creating it, because there is no
// portable way to ask and a wrong "yes" is what puts a vault somewhere that
// cannot be written. A configured path is never a candidate to fall back from:
// if the operator named it, a failure is a failure and not a reason to open a
// different vault.
func chooseVault(cfg config.Config) (vaultChoice, error) {
	if cfg.Vault != "" {
		abs, err := filepath.Abs(cfg.Vault)
		if err != nil {
			return vaultChoice{}, fmt.Errorf("resolve %s: %w", cfg.Vault, err)
		}
		return vaultChoice{Root: filepath.Clean(abs), Source: sourceOf(cfg.VaultSource)}, nil
	}

	exe, err := os.Executable()
	if err == nil {
		root := filepath.Join(filepath.Dir(exe), "vault")
		if mkErr := os.MkdirAll(root, 0o700); mkErr == nil {
			return vaultChoice{Root: root, Source: sourceDefault}, nil
		} else if fallback, fbErr := dataDirVault(); fbErr == nil {
			return vaultChoice{
				Root:     fallback,
				Source:   sourceDataDir,
				Warnings: []string{"the directory holding the executable is not writable (" + mkErr.Error() + "), so the vault was opened in the platform data directory instead"},
			}, nil
		}
	}

	// os.Executable failed, which happens in a stripped container. The working
	// directory is the only remaining answer that is not a guess about a
	// per-user location, and it is named in the banner so the operator can see
	// where the vault went.
	wd, err := os.Getwd()
	if err != nil {
		return vaultChoice{}, fmt.Errorf("no vault path was given and the executable's directory is unknown: %w", err)
	}
	root := filepath.Join(wd, "vault")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return vaultChoice{}, fmt.Errorf("create the vault beside the working directory: %w", err)
	}
	return vaultChoice{
		Root:     root,
		Source:   "default: the working directory",
		Warnings: []string{"the executable's own path is unknown, so the vault was opened beside the working directory"},
	}, nil
}

// sourceOf normalises a configured source label, for a Config a caller built by
// hand rather than through config.Load.
func sourceOf(label string) string {
	if label == "" {
		return sourceConfigured
	}
	return label
}

// dataDirVault is the last-resort location from the plan: the platform's data
// directory for this application, which is writable on a machine where the
// executable sits somewhere read-only.
func dataDirVault() (string, error) {
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			return filepath.Join(dir, config.DataDirName), nil
		}
	}
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, config.DataDirName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", config.DataDirName), nil
}

// ensureVault creates the vault root and its private directory at 0700 and
// tightens the modes of both if they already existed.
//
// The mode is not hygiene: under ADR-0004 every secret is plaintext in the
// vault, so a vault directory that is world-readable is a DM's campaign
// published to every account on the machine. An existing vault is chmod'ed
// rather than only checked, for the same reason store.Open tightens the
// database's mode.
func ensureVault(root string) error {
	for _, dir := range []string{root, filepath.Join(root, vault.HiddenDir)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("secure the permissions of %s: %w", dir, err)
		}
	}
	return nil
}

// campaignName is the label the header and the banner show for this vault.
//
// It is the vault directory's own name. No campaign name is stored anywhere —
// not in config, not in the schema — and the one thing in a vault that could
// supply one is a page's title, which is vault content and must never be
// printed by a boot report. So the name shown is the one the operator chose
// when they made the directory, which is honest and leaks nothing.
func campaignName(root string) string {
	if base := filepath.Base(root); base != "" && base != "." && base != string(filepath.Separator) {
		return base
	}
	return root
}
