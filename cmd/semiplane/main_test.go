package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/app"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
)

func TestVersionNeedsNoVault(t *testing.T) {
	t.Parallel()
	// A path that cannot be a vault: the command reports what was linked into
	// the binary and never resolves, creates or locks anything.
	nowhere := filepath.Join(t.TempDir(), "not-a-vault")
	var stdout, stderr bytes.Buffer

	if code := run([]string{"version", "--vault", nowhere}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exited %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != app.Info().String() {
		t.Errorf("version printed %q, want %q", got, app.Info().String())
	}
	if _, err := os.Stat(nowhere); !os.IsNotExist(err) {
		t.Errorf("version touched the vault path: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("version wrote to stderr: %q", stderr.String())
	}
}

// TestTheCommandLineParsesTheSameWhicheverSideTheFlagsAreOn is the executable's
// half of the argv contract, and it goes through config.Load rather than
// through anything this package owns: the partition that used to live here had
// to know which flags take a value, and a flag it did not know was dropped
// rather than refused.
func TestTheCommandLineParsesTheSameWhicheverSideTheFlagsAreOn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		args    []string
		command string
		want    config.Config
	}{
		{
			name:    "flag before the subcommand",
			args:    []string{"--vault", "/tmp/v", "reindex"},
			command: "reindex",
			want:    config.Config{Vault: "/tmp/v", VaultSource: "flag:--vault"},
		},
		{
			name:    "flag after the subcommand",
			args:    []string{"reindex", "--vault", "/tmp/v"},
			command: "reindex",
			want:    config.Config{Vault: "/tmp/v", VaultSource: "flag:--vault"},
		},
		{
			name:    "restore takes its directory after the subcommand",
			args:    []string{"restore", "--from", "20260928T100411Z", "--force"},
			command: "restore",
			want:    config.Config{RestoreFrom: "20260928T100411Z", Force: true},
		},
		{
			name:    "restore takes its directory before the subcommand",
			args:    []string{"--from", "20260928T100411Z", "restore", "--force"},
			command: "restore",
			want:    config.Config{RestoreFrom: "20260928T100411Z", Force: true},
		},
		{
			name:    "backup out after the subcommand",
			args:    []string{"backup", "--out", "/tmp/copies"},
			command: "backup",
			want:    config.Config{BackupOut: "/tmp/copies"},
		},
		{
			name:    "a vault path that looks like a command is a path",
			args:    []string{"--vault", "/srv/vault/plugins", "backup"},
			command: "backup",
			want:    config.Config{Vault: "/srv/vault/plugins", VaultSource: "flag:--vault"},
		},
		{
			// The dangerous shape: a subcommand's own flag followed by a global
			// one. If the global flag were dropped, the command would open a
			// different vault than the operator named.
			name:    "a subcommand flag before a global flag",
			args:    []string{"reindex", "--full", "--vault", "/tmp/v"},
			command: "reindex",
			want:    config.Config{Vault: "/tmp/v", VaultSource: "flag:--vault"},
		},
		{
			name:    "a subcommand and its operand before a global flag",
			args:    []string{"vault", "info", "--vault", "/tmp/v"},
			command: "vault",
			want:    config.Config{Vault: "/tmp/v", VaultSource: "flag:--vault"},
		},
		{
			name:    "a global flag between a subcommand and its operand",
			args:    []string{"vault", "--vault", "/tmp/v", "info"},
			command: "vault",
			want:    config.Config{Vault: "/tmp/v", VaultSource: "flag:--vault"},
		},
		{
			name:    "no subcommand at all",
			args:    []string{"--port", "9000"},
			command: "",
			want:    config.Config{Port: 9000},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			cfg, err := config.Load(tt.args, &stderr)
			if err != nil {
				t.Fatalf("load %v: %v (stderr %s)", tt.args, err, stderr.String())
			}
			if cfg.Command != tt.command {
				t.Errorf("command is %q, want %q", cfg.Command, tt.command)
			}
			if cfg.Vault != tt.want.Vault {
				t.Errorf("vault is %q, want %q", cfg.Vault, tt.want.Vault)
			}
			if cfg.VaultSource != tt.want.VaultSource {
				t.Errorf("vault source is %q, want %q", cfg.VaultSource, tt.want.VaultSource)
			}
			if cfg.RestoreFrom != tt.want.RestoreFrom {
				t.Errorf("restore from is %q, want %q", cfg.RestoreFrom, tt.want.RestoreFrom)
			}
			if cfg.Force != tt.want.Force {
				t.Errorf("force is %t, want %t", cfg.Force, tt.want.Force)
			}
			if cfg.BackupOut != tt.want.BackupOut {
				t.Errorf("backup out is %q, want %q", cfg.BackupOut, tt.want.BackupOut)
			}
			if tt.want.Port != 0 && cfg.Port != tt.want.Port {
				t.Errorf("port is %d, want %d", cfg.Port, tt.want.Port)
			}
		})
	}
}

// TestAnUnknownFlagIsAUsageError is the other half of accepting a subcommand's
// own flags: config passes an argument it does not recognise through to the
// command, so a typo in one of *those* has to be refused here. A
// `reindex --ful` that ran anyway would report a completed reindex of a vault
// the operator asked to rebuild in full.
func TestAnUnknownFlagIsAUsageError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		want string
		// usage is whether this executable prints its own usage line. A flag
		// config does not define is refused by the flag package, which prints
		// the flag set's usage; one that reaches a command is refused here, and
		// the operator needs the command list to see what they may have meant.
		usage bool
	}{
		{"a typo in a subcommand's own flag", []string{"reindex", "--ful"}, "--ful", true},
		{"a flag no command claims", []string{"backup", "--nosuchflag"}, "--nosuchflag", true},
		{"a flag on the default command", []string{"--port", "9000", "serve", "--full"}, "--full", true},
		{"a typo on its own", []string{"--nosuchflag"}, "nosuchflag", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("exited %d, want %d (stderr %s)", code, exitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("the refusal does not name %q: %q", tt.want, stderr.String())
			}
			if tt.usage && !strings.Contains(stderr.String(), "usage: semiplane") {
				t.Errorf("the refusal does not print the usage: %q", stderr.String())
			}
		})
	}
}

// TestTheUsageNamesEveryCommand keeps the one list this package has honest: a
// command run can dispatch but the usage does not mention is a command the help
// does not promise.
func TestTheUsageNamesEveryCommand(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"reindex", "backup", "restore", "vault info", "plugins list", "version", "serve"} {
		if !strings.Contains(usageLine, command) {
			t.Errorf("the usage line does not mention %q: %s", command, usageLine)
		}
	}
}

// TestHelpIsZeroExitWhicheverSideItIsWritten covers --help before and after a
// subcommand. Only the first is answered by config, so the second is the
// executable's to answer: refusing it would be worse than both printing the
// usage and, as it used to, quietly reindexing the vault instead.
func TestHelpIsZeroExitWhicheverSideItIsWritten(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--help"},
		{"-h"},
		{"reindex", "--help"},
		{"vault", "info", "-h"},
		{"reindex", "--full", "--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			// A path that cannot be a vault: a help request must be answered
			// before anything is resolved, locked or opened.
			nowhere := filepath.Join(t.TempDir(), "not-a-vault")
			var stdout, stderr bytes.Buffer
			if code := run(append(args, "--vault", nowhere), &stdout, &stderr); code != exitOK {
				t.Fatalf("exited %d, want 0 (stderr: %s)", code, stderr.String())
			}
			if _, err := os.Stat(nowhere); !os.IsNotExist(err) {
				t.Errorf("the help request touched the vault path: %v", err)
			}
		})
	}
}

func TestHasFlagAcceptsBothSpellings(t *testing.T) {
	t.Parallel()
	args := []string{"-full", "--force", "--allow-case-collisions=true"}
	for name, want := range map[string]bool{"--full": true, "-full": true, "--force": true, "--nope": false} {
		if got := hasFlag(args, name); got != want {
			t.Errorf("hasFlag(%q) is %t, want %t", name, got, want)
		}
	}
}

func TestPluginsListReportsNothingRatherThanInventingAnEntry(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"plugins", "list"}, &stdout, &stderr); code != 0 {
		t.Fatalf("plugins list exited %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "0 plugins registered") {
		t.Errorf("plugins list did not report the truth: %q", stdout.String())
	}
}

func TestAnUnknownCommandIsAUsageError(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"frobnicate"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("an unknown command exited %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "frobnicate") {
		t.Errorf("the refusal does not name the command: %q", stderr.String())
	}
}

// TestReindexFromTheCommandLine is the whole path end to end: argv, config, the
// composition root, the index, and the exit code.
func TestReindexFromTheCommandLine(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "One.md"), []byte("# One\n\nThe first page.\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"reindex", "--full", "--vault", root}, &stdout, &stderr); code != exitOK {
		t.Fatalf("reindex exited %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "reindexed 1 pages from 1 files") {
		t.Errorf("the command did not report the pass:\n%s", stdout.String())
	}
	// The lock is released on the way out, or a second run is refused.
	var again bytes.Buffer
	if code := run([]string{"vault", "info", "--vault", root}, &again, &stderr); code != exitOK {
		t.Fatalf("vault info after reindex exited %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(again.String(), "pages:") && !strings.Contains(again.String(), "index:") {
		t.Errorf("vault info printed no report:\n%s", again.String())
	}
}
