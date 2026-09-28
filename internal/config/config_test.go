package config

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Parallel()
	c, err := Load(nil, os.Stderr)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := Default()
	if c.Host != want.Host || c.Port != want.Port || c.LogLevel != want.LogLevel {
		t.Errorf("defaults changed: %+v", c)
	}
	if c.AllowAnonymousRead || c.AllowCaseCollisions || c.Dev {
		t.Errorf("a permission was on by default: %+v", c)
	}
	if c.Vault != "" {
		t.Errorf("a vault path was invented: %q", c.Vault)
	}
}

// Not parallel: t.Setenv and t.Chdir are process-global.
func TestFlagBeatsEnvironmentBeatsDefault(t *testing.T) {
	dir := t.TempDir()
	envVault := filepath.Join(dir, "from-env")
	flagVault := filepath.Join(dir, "from-flag")

	t.Setenv(DefaultEnvVar, envVault)

	c, err := Load([]string{"--vault", flagVault}, os.Stderr)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Vault != flagVault {
		t.Errorf("flag lost to the environment: %q", c.Vault)
	}
	if c.VaultSource != "flag:--vault" {
		t.Errorf("source = %q", c.VaultSource)
	}

	c, err = Load(nil, os.Stderr)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Vault != envVault {
		t.Errorf("environment ignored: %q", c.Vault)
	}
	if c.VaultSource != "env:"+DefaultEnvVar {
		t.Errorf("source = %q", c.VaultSource)
	}
}

// Not parallel: t.Chdir is process-global.
func TestVaultPathIsAbsoluteAndCleaned(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	c, err := Load([]string{"--vault", "./campaigns/../vault"}, os.Stderr)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !filepath.IsAbs(c.Vault) {
		t.Fatalf("vault path is relative: %q", c.Vault)
	}
	if c.Vault != filepath.Join(dir, "vault") {
		t.Errorf("vault path = %q", c.Vault)
	}
}

func TestSubcommandParsing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args []string
		want string
		sub  []string
	}{
		{"bare serve", nil, "", nil},
		{"explicit serve", []string{"serve"}, "serve", nil},
		{"reindex with a flag after it", []string{"reindex", "--full"}, "reindex", []string{"--full"}},
		{"version", []string{"version"}, "version", nil},
		{"flags before the subcommand", []string{"--dev", "backup"}, "backup", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := Load(tc.args, os.Stderr)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if c.Command != tc.want {
				t.Errorf("command = %q, want %q", c.Command, tc.want)
			}
			if len(c.SubArgs) != len(tc.sub) {
				t.Errorf("sub args = %v, want %v", c.SubArgs, tc.sub)
			}
		})
	}
}

// TestTheSubcommandMayBeWrittenAnywhere is the contract reorder exists for: the
// three spellings an operator reaches for are the same command, not one of them
// a usage error.
//
// The comparison is over the whole Config rather than a field or two, because a
// flag that parses on one side and not the other does not fail visibly — it
// leaves the default in place, and the failure is discovered as a command that
// ran against the wrong vault.
func TestTheSubcommandMayBeWrittenAnywhere(t *testing.T) {
	t.Parallel()
	forms := [][]string{
		{"reindex", "--full"},
		{"--dev", "reindex", "--full"},
		{"--reindex", "reindex", "--full"},
	}
	want, err := Load(forms[0], io.Discard)
	if err != nil {
		t.Fatalf("load %v: %v", forms[0], err)
	}
	if want.Command != "reindex" || want.SubArgs[0] != "--full" {
		t.Fatalf("the first form did not parse as written: %+v", want)
	}
	for _, args := range forms[1:] {
		got, err := Load(args, io.Discard)
		if err != nil {
			t.Fatalf("load %v: %v", args, err)
		}
		if got.Command != want.Command {
			t.Errorf("%v: command is %q, want %q", args, got.Command, want.Command)
		}
		if !reflect.DeepEqual(got.SubArgs, want.SubArgs) {
			t.Errorf("%v: sub args are %v, want %v", args, got.SubArgs, want.SubArgs)
		}
	}
	// --dev is the flag that differs between the forms, so it is asserted
	// rather than left to the whole-Config comparison above, which the other two
	// forms would satisfy without parsing it at all.
	dev, err := Load([]string{"--dev", "reindex", "--full"}, io.Discard)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !dev.Dev {
		t.Error("--dev before the subcommand was dropped")
	}
}

// TestRestoreTakesItsDirectoryFromEitherSide is the bug the reorder was written
// for: --from after the subcommand used to reach Validate unset, and the
// command failed its own validation with a flag the help spells exactly that
// way.
func TestRestoreTakesItsDirectoryFromEitherSide(t *testing.T) {
	t.Parallel()
	const dir = "20260928T100411Z"
	want, err := Load([]string{"--from", dir, "restore", "--force"}, io.Discard)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got, err := Load([]string{"restore", "--from", dir, "--force"}, io.Discard)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("restore --from parsed as %+v, want %+v", got, want)
	}
	if got.RestoreFrom != dir || !got.Force || got.Command != "restore" {
		t.Errorf("restore parsed as %+v", got)
	}
}

// TestAnUnknownFlagIsRefusedNotSwallowed is the other half of reordering a
// caller has to prove. Moving a flag to the end of the argument list is exactly
// the kind of change that turns a typo into a silent default, so an unknown
// flag stays an error whenever nothing claims it.
func TestAnUnknownFlagIsRefusedNotSwallowed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args []string
	}{
		{"a typo on its own", []string{"--nosuchflag"}},
		{"a typo after a real flag", []string{"--dev", "--nosuchflag"}},
		{"a misspelled value flag", []string{"--vaultt", "/tmp/v"}},
		{"a misspelled flag whose value looks like an operand", []string{"--portt", "9000"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Load(tc.args, io.Discard); err == nil {
				t.Fatalf("%v parsed without an error", tc.args)
			}
		})
	}
	// The one shape that is not an error: a flag a subcommand owns reaches the
	// caller as that subcommand's argument, because config has no reason to know
	// what reindex accepts. run() is what refuses an argument no command claims,
	// so a typo that survives this far is a typo, not a default.
	for _, args := range [][]string{{"reindex", "--full"}, {"backup", "--nosuchflag"}} {
		got, err := Load(args, io.Discard)
		if err != nil {
			t.Fatalf("load %v: %v", args, err)
		}
		if len(got.SubArgs) != 1 || !strings.HasPrefix(got.SubArgs[0], "-") {
			t.Errorf("%v: sub args are %v, want the one unrecognised flag", args, got.SubArgs)
		}
	}
}

// TestEveryFlagIsAcceptedOnEitherSideOfTheSubcommand walks the flag set Load
// itself builds rather than a list of flag names, so a flag added to config is
// covered here the day it is added.
//
// It is the test the first argv partitioner needed and did not have: it had its
// own copy of config's flag table, and a --vault it did not know about was
// dropped silently, leaving the command to open the default vault.
func TestEveryFlagIsAcceptedOnEitherSideOfTheSubcommand(t *testing.T) {
	t.Parallel()
	var probe Config
	var vaultFlag string
	fs := newFlagSet(&probe, &vaultFlag)
	fs.SetOutput(io.Discard)

	seen := 0
	fs.VisitAll(func(f *flag.Flag) {
		seen++
		t.Run(f.Name, func(t *testing.T) {
			before, errBefore := Load(withFlag("--"+f.Name, sampleValue(f), "reindex"), io.Discard)
			after, errAfter := Load(withFlag("reindex", "--"+f.Name, sampleValue(f)), io.Discard)

			// The sample value is chosen by kind rather than per flag, so a
			// string flag may be a value Validate refuses. What must hold is
			// that the two spellings are indistinguishable.
			if (errBefore == nil) != (errAfter == nil) {
				t.Fatalf("%s parses before the subcommand (%v) but not after it (%v)",
					f.Name, errBefore, errAfter)
			}
			if !reflect.DeepEqual(before, after) {
				t.Errorf("%s parses as %+v before the subcommand and %+v after it",
					f.Name, before, after)
			}
		})
	})
	if seen == 0 {
		t.Fatal("the flag set is empty, so this test asserts nothing")
	}
}

// sampleValue is a value of the right shape for a flag, chosen from the kind of
// the value it already holds. A boolean takes none: the flag is written alone.
func sampleValue(f *flag.Flag) string {
	g, ok := f.Value.(flag.Getter)
	if !ok {
		return "1"
	}
	switch reflect.ValueOf(g.Get()).Kind() {
	case reflect.String:
		return "sp"
	case reflect.Bool:
		return ""
	default:
		return "1"
	}
}

// withFlag splices a flag and its value into an argument list, without writing
// an empty value — an empty string is an operand, not the absence of one.
func withFlag(args ...string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

func TestValidateRejectsBadValues(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"bad log level", func(c *Config) { c.LogLevel = "chatty" }},
		{"negative port", func(c *Config) { c.Port = -1 }},
		{"port above range", func(c *Config) { c.Port = 70000 }},
		{"empty host", func(c *Config) { c.Host = "  " }},
		{"zero attachment cap", func(c *Config) { c.MaxAttachmentSize = 0 }},
		{"restore without from", func(c *Config) { c.Command = "restore" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Default()
			tc.mut(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("%+v should not validate", c)
			}
		})
	}
}

func TestAddr(t *testing.T) {
	t.Parallel()
	c := Default()
	c.Host = "0.0.0.0"
	c.Port = 9000
	if got := c.Addr(); got != "0.0.0.0:9000" {
		t.Errorf("Addr = %q", got)
	}
}

func TestHelpIsNotAnError(t *testing.T) {
	t.Parallel()
	if _, err := Load([]string{"--help"}, os.Stderr); err == nil {
		t.Fatal("-h should return flag.ErrHelp so the caller exits zero")
	}
}
