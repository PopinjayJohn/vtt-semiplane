package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// The Argon2id cost parameters agreed in S9. They are exported so that the test
// that pins them asserts on the encoded string rather than on a constant that
// could drift away from the value actually used, and so that changing one is a
// deliberate act.
const (
	// ArgonMemoryKiB is the memory cost: 64 MiB per hash.
	ArgonMemoryKiB uint32 = 64 * 1024
	// ArgonTime is the number of passes over the memory.
	ArgonTime uint32 = 3
	// ArgonThreads is the degree of parallelism.
	ArgonThreads uint8 = 1
)

const (
	// argonKeyLen is the derived key length. It is not exported because it is
	// part of the hash, not a policy knob: changing it makes every stored hash
	// unverifiable, so it moves only with a new PHC version.
	argonKeyLen uint32 = 32
	// argonSaltLen is the salt length in bytes.
	argonSaltLen = 16
)

// MaxVerifyMemoryKiB bounds the memory a stored hash may ask for when it is
// verified.
//
// The parameters travel inside the hash so they can be raised later, which
// means a row in the database is a request to allocate. The database is inside
// the vault and a vault is a directory somebody can edit, so the ceiling is
// enforced in Go rather than trusted. 256 MiB leaves room to quadruple the cost
// without a second mechanism, and is small enough that a hostile row cannot
// make a login page unanswerable.
const MaxVerifyMemoryKiB uint32 = 256 * 1024

// The other two parameters are bounded for the same reason. Neither bound is
// reachable by anything this binary writes.
const (
	maxVerifyTime    uint32 = 64
	maxVerifyThreads uint8  = 16
)

// ErrMalformedHash reports a stored hash that is not a well-formed Argon2id
// PHC string. It is a distinct sentinel from a wrong passphrase because it
// means the database is damaged rather than the input wrong, and the two must
// never be rendered the same way.
var ErrMalformedHash = errors.New("malformed argon2id hash")

// argonParams is a decoded PHC string.
type argonParams struct {
	// memoryKiB is the m cost.
	memoryKiB uint32
	// time is the t cost.
	time uint32
	// threads is the p cost.
	threads uint8
	// salt is the decoded salt.
	salt []byte
	// key is the derived key to compare against.
	key []byte
}

// encodePHC renders salt and key in the PHC string format, which carries the
// algorithm, the version and the three costs alongside the hash. A bare digest
// would have to be interpreted with a compile-time constant, and raising the
// cost later would then invalidate every existing account.
func encodePHC(salt, key []byte, memoryKiB uint32, passes uint32, threads uint8) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, passes, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// parsePHC decodes a PHC string, refusing anything outside the bounds above.
// A decode failure is ErrMalformedHash and never a partial success: a hash this
// function did not fully understand must not reach argon2.
func parsePHC(encoded string) (argonParams, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return argonParams{}, fmt.Errorf("%w: not an argon2id PHC string", ErrMalformedHash)
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil || version != argon2.Version {
		return argonParams{}, fmt.Errorf("%w: unsupported version %q", ErrMalformedHash, parts[2])
	}
	p, err := parseCost(parts[3])
	if err != nil {
		return argonParams{}, err
	}
	if p.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return argonParams{}, fmt.Errorf("%w: salt is not base64", ErrMalformedHash)
	}
	if p.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return argonParams{}, fmt.Errorf("%w: digest is not base64", ErrMalformedHash)
	}
	if len(p.key) == 0 {
		return argonParams{}, fmt.Errorf("%w: empty digest", ErrMalformedHash)
	}
	return p, nil
}

// costSeen tracks which of m, t and p a cost string named. A PHC string that
// omits one is malformed rather than defaulted: the parameters are how a
// future raise stays readable, and a missing one would be read as today's
// value forever.
type costSeen uint8

const (
	seenM costSeen = 1 << iota
	seenT
	seenP
)

func parseCost(in string) (argonParams, error) {
	var (
		p    argonParams
		seen costSeen
	)
	for _, kv := range strings.Split(in, ",") {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			return argonParams{}, fmt.Errorf("%w: cost %q has no '='", ErrMalformedHash, kv)
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return argonParams{}, fmt.Errorf("%w: cost %q is not a number", ErrMalformedHash, key)
		}
		switch key {
		case "m":
			if n == 0 || uint32(n) > MaxVerifyMemoryKiB {
				return argonParams{}, fmt.Errorf("%w: m=%d is outside 1..%d KiB", ErrMalformedHash, n, MaxVerifyMemoryKiB)
			}
			p.memoryKiB = uint32(n)
			seen |= seenM
		case "t":
			if n == 0 || uint32(n) > maxVerifyTime {
				return argonParams{}, fmt.Errorf("%w: t=%d is outside 1..%d", ErrMalformedHash, n, maxVerifyTime)
			}
			p.time = uint32(n)
			seen |= seenT
		case "p":
			if n == 0 || n > uint64(maxVerifyThreads) {
				return argonParams{}, fmt.Errorf("%w: p=%d is outside 1..%d", ErrMalformedHash, n, maxVerifyThreads)
			}
			p.threads = uint8(n)
			seen |= seenP
		default:
			return argonParams{}, fmt.Errorf("%w: unknown cost key %q", ErrMalformedHash, key)
		}
	}
	if seen != seenM|seenT|seenP {
		return argonParams{}, fmt.Errorf("%w: cost %q is missing m, t or p", ErrMalformedHash, in)
	}
	return p, nil
}

// derive runs the Argon2id key derivation at the given costs.
//
// The full-cost counter exists because the agreed parameters cost about 140 ms
// on an ordinary machine, and a test suite that quietly grew a few hundred real
// derivations would still be green while taking half a minute. It is the only
// instrumentation in this file, and it counts rather than times, so a slow test
// run reports a number a reader can act on.
func derive(salt []byte, passphrase string, memoryKiB uint32, passes uint32, threads uint8) []byte {
	if memoryKiB == ArgonMemoryKiB && passes == ArgonTime && threads == ArgonThreads {
		fullCostDerivations.Add(1)
	}
	return argon2.IDKey([]byte(passphrase), salt, passes, memoryKiB, threads, argonKeyLen)
}

// fullCostDerivations counts the derivations run at the production costs. It is
// a sync/atomic counter, which AGENTS.md allows at package level, and it is read
// by the test budget in TestMain.
var fullCostDerivations atomic.Int64

// HashPassphrase derives an Argon2id verifier for a passphrase and returns it
// in PHC form. The whole string belongs in users.pw_hash: it is the only record
// from which the verifier can be rebuilt, and splitting the salt out into
// users.pw_salt for its own sake would create two records that can disagree.
func HashPassphrase(passphrase string) (string, error) {
	return hashPassphraseWith(passphrase, ArgonMemoryKiB, ArgonTime, ArgonThreads)
}

// hashPassphraseWith is HashPassphrase at explicit costs.
//
// It is unexported so that the production costs cannot be chosen by a caller —
// a caller who could pass m=8 would, eventually, by accident — and it exists
// because the encoding is a thing worth testing without paying 64 MiB per
// assertion, and because the rehash-on-login that raising these costs will need
// has to land somewhere.
func hashPassphraseWith(passphrase string, memoryKiB uint32, passes uint32, threads uint8) (string, error) {
	if err := ValidatePassphrase(passphrase); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read passphrase salt: %w", err)
	}
	key := derive(salt, passphrase, memoryKiB, passes, threads)
	return encodePHC(salt, key, memoryKiB, passes, threads), nil
}

// SaltFromPHC returns the raw salt embedded in an encoded hash. It exists
// because users.pw_salt is NOT NULL: the column is filled from the same string
// the verifier is read out of, so the two can never be different salts.
func SaltFromPHC(encoded string) ([]byte, error) {
	p, err := parsePHC(encoded)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), p.salt...), nil
}

// Verify reports whether passphrase is the one an encoded Argon2id hash was
// derived from. A hash that will not parse is ErrMalformedHash, never a false.
//
// The comparison is constant time for a per-account reason rather than an
// absolute one: the derived key and the stored key are always the same length,
// because the length is read out of the same string, so subtle's early return
// on a length mismatch can never fire and cannot encode anything about the
// passphrase.
func Verify(encoded []byte, passphrase string) (bool, error) {
	p, err := parsePHC(string(encoded))
	if err != nil {
		return false, err
	}
	key := argon2.IDKey([]byte(passphrase), p.salt, p.time, p.memoryKiB, p.threads, uint32(len(p.key)))
	return subtle.ConstantTimeCompare(key, p.key) == 1, nil
}

// dummyPassphrase is the value the dummy verifier is derived from. Nothing can
// be typed into a login form that matches it, and TestTheDummyVerifierMatchesNothing
// asserts that as a fact rather than as an intention.
const dummyPassphrase = "auth: there is no account with that name"

// dummyHash is a real Argon2id verifier at the production costs, over a fresh
// salt. A login for an account that does not exist runs it so the answer takes
// the same time as one for an account that does. Without it, the difference
// between a miss and a wrong passphrase is the difference between a table
// lookup and 64 MiB of memory-hard work, which is a username oracle.
//
// It is memoised rather than computed per call because 64 MiB of argon2 on
// every rejected login would be a denial of service of our own making, and
// because the value is a constant dressed as a value.
var dummyHash = sync.OnceValue(func() string {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return ""
	}
	return encodePHC(salt, derive(salt, dummyPassphrase, ArgonMemoryKiB, ArgonTime, ArgonThreads),
		ArgonMemoryKiB, ArgonTime, ArgonThreads)
})

// burnVerify spends the CPU one real verification would spend and throws the
// answer away. It is the whole of the unknown-account defence.
func burnVerify(passphrase string) {
	if hash := dummyHash(); hash != "" {
		_, _ = Verify([]byte(hash), passphrase)
	}
}

// MinPassphraseLen is the shortest accepted passphrase.
const MinPassphraseLen = 10

// ErrWeakPassphrase is the sentinel every passphrase rejection matches, so a
// caller can render one message without inspecting the reason.
var ErrWeakPassphrase = errors.New("passphrase rejected")

// PassphraseError is a rejected passphrase and the rule it broke. It carries a
// reason rather than the passphrase, and the reason is always a fixed phrase
// from this file: nothing a caller typed is ever echoed back, because an error
// message is a thing that gets logged.
type PassphraseError struct {
	// Reason is a short phrase for the UI. It is safe to render.
	Reason string
}

func (e *PassphraseError) Error() string { return "auth: passphrase " + e.Reason }

// Unwrap makes errors.Is(err, ErrWeakPassphrase) true.
func (e *PassphraseError) Unwrap() error { return ErrWeakPassphrase }

// ValidatePassphrase applies the cheap composition rules. It is a guard against
// the passphrases people actually pick, not a strength estimate: a rule this
// short cannot tell a bad passphrase from a good one, and argon2 is what makes
// guessing expensive.
func ValidatePassphrase(passphrase string) error {
	if utf8.RuneCountInString(passphrase) < MinPassphraseLen {
		return &PassphraseError{Reason: fmt.Sprintf("must be at least %d characters", MinPassphraseLen)}
	}
	var (
		mask     uint8
		first    rune
		repeated = true
	)
	for i, r := range passphrase {
		if i == 0 {
			first = r
		} else if r != first {
			repeated = false
		}
		mask |= classOf(r)
	}
	if repeated {
		return &PassphraseError{Reason: "must not be one character repeated"}
	}
	if bits.OnesCount8(mask) < 2 {
		return &PassphraseError{Reason: "must mix cases, digits or symbols"}
	}
	return nil
}
