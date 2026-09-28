package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Defaults.
const (
	// DefaultHost binds to loopback. LAN hosting is opt-in with --host
	// 0.0.0.0, because the app holds plaintext DM secrets and guest wifi on a
	// LAN is not a trusted network.
	DefaultHost = "127.0.0.1"
	// DefaultPort is the listening port.
	DefaultPort = 8080
	// DefaultEnvVar is the environment variable that overrides the vault path.
	DefaultEnvVar = "SEMIPLANE_VAULT"
	// DefaultLogLevel is the slog level used when none is given.
	DefaultLogLevel = "info"
	// DataDirName is the per-platform data directory under which the vault
	// falls back when the executable's directory is not writable.
	DataDirName = "vtt-semiplane"
)

// ErrHelp is returned when the user asked for -h/--help. The caller prints
// usage and exits zero.
var ErrHelp = flag.ErrHelp

// Config is the validated runtime configuration. It is immutable after Load:
// nothing in the application mutates it, and it is safe to copy and to read
// from any goroutine.
type Config struct {
	// Vault is the absolute path to the vault directory. It is always
	// absolute: a relative --vault is resolved against the working directory
	// at load time and the resolved path is what gets logged on every boot.
	Vault string
	// VaultSource records how the vault path was chosen, for the boot banner.
	VaultSource string
	// Host is the bind address.
	Host string
	// Port is the listening port.
	Port int
	// AllowAnonymousRead enables unauthenticated read-only access to public
	// pages. Off by default; anonymous users never see secrets under any
	// visibility.
	AllowAnonymousRead bool
	// AllowCaseCollisions lets the indexer proceed when two vault paths
	// collide on a case-insensitive filesystem. Without it, such a vault is a
	// hard error, because one of the two pages is invisible to the walk and
	// appears to have vanished (S19).
	AllowCaseCollisions bool
	// NoOpen suppresses the browser open after binding.
	NoOpen bool
	// LogLevel is one of debug, info, warn, error.
	LogLevel string
	// Dev enables development mode: verbose request logging with bodies for
	// local routes, no rate limiting, a visible unsafe-mode banner, and the
	// /_/dev/reindex action.
	Dev bool
	// MaxAttachmentSize is the per-file upload and index cap.
	MaxAttachmentSize int64
	// Reindex forces a full reindex on boot.
	Reindex bool
	// Command is the subcommand: "", "reindex", "backup", "restore",
	// "vault", "plugins", "version".
	Command string
	// SubArgs are the arguments after the subcommand.
	SubArgs []string
	// RestoreFrom is the --from directory for the restore command.
	RestoreFrom string
	// Force allows restore to overwrite.
	Force bool
	// BackupOut is the --out directory for the backup command.
	BackupOut string
}

// Default returns the configuration with no flags applied.
func Default() Config {
	return Config{
		Host:              DefaultHost,
		Port:              DefaultPort,
		LogLevel:          DefaultLogLevel,
		MaxAttachmentSize: 32 << 20,
	}
}

// newFlagSet defines every flag config understands, against c, and returns the
// set.
//
// It is a function rather than a block inside Load so that the reordering and
// the tests walk *these* definitions: a flag added here is immediately a flag
// that parses on either side of a subcommand, and a test that has to name flags
// by hand is a second list waiting to drift.
func newFlagSet(c *Config, vaultFlag *string) *flag.FlagSet {
	fs := flag.NewFlagSet("semiplane", flag.ContinueOnError)
	fs.StringVar(vaultFlag, "vault", "", "path to the vault directory (default: <exe dir>/vault)")
	fs.StringVar(&c.Host, "host", c.Host, "bind address; use 0.0.0.0 to serve the LAN")
	fs.IntVar(&c.Port, "port", c.Port, "listening port")
	fs.BoolVar(&c.AllowAnonymousRead, "allow-anonymous-read", c.AllowAnonymousRead,
		"allow unauthenticated read-only access to public pages")
	fs.BoolVar(&c.AllowCaseCollisions, "allow-case-collisions", c.AllowCaseCollisions,
		"index a vault whose paths collide on a case-insensitive filesystem")
	fs.BoolVar(&c.NoOpen, "no-open", c.NoOpen, "do not open a browser after binding")
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "debug, info, warn or error")
	fs.BoolVar(&c.Dev, "dev", c.Dev, "development mode: verbose logging, no rate limiting, unsafe-mode banner")
	fs.Int64Var(&c.MaxAttachmentSize, "max-attachment-size", c.MaxAttachmentSize,
		"maximum attachment size in bytes")
	fs.BoolVar(&c.Reindex, "reindex", false, "force a full reindex on boot")
	fs.StringVar(&c.RestoreFrom, "from", "", "backup directory to restore from")
	fs.BoolVar(&c.Force, "force", false, "overwrite the current vault when restoring")
	fs.StringVar(&c.BackupOut, "out", "", "directory to write a backup to")
	return fs
}

// Load parses args (without the program name), layering flag > environment >
// default, and validates the result. The returned Config is safe to use; any
// error means nothing has been opened yet.
//
// The subcommand may be written anywhere, and its flags on either side of it:
// `semiplane reindex --full`, `semiplane --dev reindex --full` and `semiplane
// restore --from DIR` all parse, and a flag config does not define is left to
// the subcommand as one of its own arguments. See reorder for why the arguments
// are put in order here rather than by the caller.
//
// A flag that is still unknown once the operands have been read is an error,
// not a default: `semiplane --nosuchflag` must be refused rather than quietly
// run the app on the default vault.
func Load(args []string, stderr io.Writer) (Config, error) {
	c := Default()

	var vaultFlag string
	fs := newFlagSet(&c, &vaultFlag)
	fs.SetOutput(stderr)

	// The environment is read before flag.Parse so that a flag still wins,
	// which is what a caller expects when they pass both.
	if v := os.Getenv(DefaultEnvVar); v != "" {
		c.Vault = v
		c.VaultSource = "env:" + DefaultEnvVar
	}
	if v := os.Getenv("SEMIPLANE_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}

	if err := fs.Parse(reorder(fs, args)); err != nil {
		return c, err
	}
	if vaultFlag != "" {
		c.Vault = vaultFlag
		c.VaultSource = "flag:--vault"
	}

	rest := fs.Args()
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		c.Command = rest[0]
		c.SubArgs = rest[1:]
	}

	if c.Vault != "" {
		abs, err := filepath.Abs(c.Vault)
		if err != nil {
			return c, fmt.Errorf("resolving vault path: %w", err)
		}
		c.Vault = filepath.Clean(abs)
	}

	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

// Validate checks the resolved configuration. It returns the first problem
// found; error messages are lowercase and unpunctuated.
func (c Config) Validate() error {
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid log level %q: want debug, info, warn or error", c.LogLevel)
	}
	if c.Port < 0 || c.Port > 65535 {
		return errors.New("invalid port: must be between 0 and 65535")
	}
	if strings.TrimSpace(c.Host) == "" {
		return errors.New("invalid host: must not be empty")
	}
	if c.MaxAttachmentSize <= 0 {
		return errors.New("invalid max attachment size: must be positive")
	}
	if c.Command == "restore" && c.RestoreFrom == "" {
		return errors.New("restore requires --from")
	}
	return nil
}

// Addr is the listen address.
func (c Config) Addr() string { return net.JoinHostPort(c.Host, strconv.Itoa(c.Port)) }

// SessionTTL is the absolute session lifetime (U2).
const SessionTTL = 14 * 24 * time.Hour

// SessionSlide is the sliding refresh threshold: a session that has not been
// seen for this long has its expiry extended, up to the absolute limit.
const SessionSlide = 7 * 24 * time.Hour

// InviteTTL is how long a single-use invite stays valid.
const InviteTTL = 72 * time.Hour

// Rate limit defaults (U12), per IP token bucket.
const (
	RateLoginPerMinute   = 10
	RateSearchPerMinute  = 30
	RateSessionPerMinute = 300
)
