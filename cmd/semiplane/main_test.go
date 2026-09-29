package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/app"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/sample"
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

// TestPluginsListReportsTheRegistryRatherThanACount pins the intent the old
// version of this test got right and its assertion wrong: `plugins list` must
// not invent an entry, and neither may it invent an empty one.
//
// The oracle is the registry itself, which is the one place in the tree allowed
// to name a plugin id. A hard-coded count would pass on a build that ships a
// fourth plugin and fail on one that ships two, and it says nothing about which
// entries are there — so the assertion is on the set of ids the table carries,
// compared against the set the registry offers.
func TestPluginsListReportsTheRegistryRatherThanACount(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"plugins", "list"}, &stdout, &stderr); code != 0 {
		t.Fatalf("plugins list exited %d (stderr: %s)", code, stderr.String())
	}

	offered := builtinPlugins()
	listed := tableIDs(t, stdout.String())
	if len(listed) != len(offered) {
		t.Errorf("the table has %d rows (%v) and the registry offers %d (%v):\n%s",
			len(listed), listed, len(offered), sortedKeys(offered), stdout.String())
	}
	for id := range offered {
		if listed[id] != 1 {
			t.Errorf("the plugin %q appears %d times in the table, want once:\n%s", id, listed[id], stdout.String())
		}
	}
}

// TestPluginsListTouchesNoVault is the reason the command is not a one-shot
// boot. An operator asking what a binary has may have no vault, and a command
// that created and locked one to answer that would be a surprising price for a
// list.
func TestPluginsListTouchesNoVault(t *testing.T) {
	t.Parallel()
	nowhere := filepath.Join(t.TempDir(), "not-a-vault")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"plugins", "list", "--vault", nowhere}, &stdout, &stderr); code != 0 {
		t.Fatalf("plugins list exited %d (stderr: %s)", code, stderr.String())
	}
	if _, err := os.Stat(nowhere); !os.IsNotExist(err) {
		t.Errorf("plugins list created or opened a vault: %v", err)
	}
}

// tableIDs counts the rows of the plugins table by the id in the first column.
// The table is everything from its header to the end of the output, so a line
// before the header is prose and a line that is not a row after it is a
// malformed table — both fail rather than being skipped.
func tableIDs(t *testing.T, out string) map[string]int {
	t.Helper()
	listed := map[string]int{}
	rows := false
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if !rows {
			if len(fields) > 0 && fields[0] == "ID" {
				rows = true
			}
			continue
		}
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 {
			t.Errorf("the table has a row that is not an entry: %q\n%s", line, out)
			continue
		}
		listed[fields[0]]++
	}
	if !rows {
		t.Fatalf("there is no table at all:\n%s", out)
	}
	return listed
}

func sortedKeys(plugins map[string]plugin.Plugin) []string {
	ids := make([]string, 0, len(plugins))
	for id := range plugins {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
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
	// The boot writes the bundled campaign into this vault before it indexes
	// it, so the pass reports the one page this test seeded plus the campaign.
	// Naming the campaign's size rather than a literal is what keeps the
	// assertion about the reindex instead of about how many pages ship.
	campaign, err := sample.Files()
	if err != nil {
		t.Fatalf("the bundled sample campaign cannot be read: %v", err)
	}
	indexed := strconv.Itoa(1 + len(campaign))
	if want := "reindexed " + indexed + " pages from " + indexed + " files"; !strings.Contains(stdout.String(), want) {
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
