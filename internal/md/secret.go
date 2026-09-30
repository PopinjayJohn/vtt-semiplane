package md

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// Directive keys. The set is closed, and a key outside it makes the directive
// unreadable rather than ignored: a fence that claims to be a secret is one
// whatever its directive says, so a directive this package cannot read is a
// fence it must not serve. A fence is never public because of a typo.
const (
	KeyID         = "id"
	KeyVisibility = "visibility"
	KeyAuthor     = "author"
	KeyCreated    = "created"
	KeyTitle      = "title"
)

// SecretFenceWord is the info-string word that opens a secret fence.
const SecretFenceWord = "secret"

// Problem codes recorded by the segmenter.
const (
	// ProblemSecretUnterminated is a secret fence with no closing fence. The
	// span still extends to end of file: a secret that is dropped would be
	// rendered as plaintext, which is the one failure mode that cannot be
	// recovered from after the fact.
	ProblemSecretUnterminated = "secret.unterminated"
	// ProblemSecretNested is a secret fence inside a secret fence. The inner
	// fence cannot be secret — a secret is opaque — so it is literal text and
	// the outer span continues past it.
	ProblemSecretNested = "secret.nested"
	// ProblemSecretUnknownKey is a directive carrying a key outside the known
	// set. The fence stays secret and is hidden from everybody, fail-closed:
	// a directive whose meaning is unknown is not one this package may claim to
	// have enforced, and the body is served on the strength of a key nobody
	// read. See segmentBody.
	ProblemSecretUnknownKey = "secret.unknown_key"
	// ProblemSecretBadVisibility is a directive whose visibility is not one of
	// the three known values. The fence stays secret and falls back to
	// private, which is the direction that leaks nothing.
	ProblemSecretBadVisibility = "secret.bad_visibility"
	// ProblemSecretMissingID is a secret fence with no id. The span is still
	// secret; a deterministic placeholder derived from its byte offset is
	// assigned so that span.SecretID is never empty.
	ProblemSecretMissingID = "secret.missing_id"
	// ProblemSecretBadDirective is a fence whose info string begins with
	// `secret` but cannot be parsed at all. The fence stays secret and is
	// hidden from everybody: the fence still claimed secrecy, and the only
	// reading of a line this package cannot parse is the one that leaks
	// nothing. See segmentBody.
	ProblemSecretBadDirective = "secret.bad_directive"
	// ProblemSecretUnknownID is a reveal or revoke naming a secret the
	// document does not contain. Nothing is written; the caller's id and the
	// index have diverged, which is a bug worth surfacing rather than a state
	// worth guessing at.
	ProblemSecretUnknownID = "secret.unknown_id"

	// ProblemUnparsableIDPrefix prefixes the synthetic id given to a fence whose
	// directive could not be read. The prefix is deliberately not 12 hex
	// characters, so a fence that claims a secret and does not supply one can
	// never be mistaken for a fence that supplies a real id — by the index, by
	// the tripwire, or by anything that assumes an id is addressable.
	ProblemUnparsableIDPrefix = "unparsable-"
)

var (
	// ErrNotSecretFence reports an info string that does not begin with the
	// `secret` word.
	ErrNotSecretFence = errors.New("md: not a secret fence")
	// ErrDuplicateDirectiveKey reports a directive with the same key twice. It
	// is an error rather than a last-one-wins so that two contradictory
	// visibilities cannot be written and silently resolved.
	ErrDuplicateDirectiveKey = errors.New("md: duplicate directive key")
)

// Directive is a parsed ```secret fence directive. It is the on-disk spelling
// of a secret's metadata, kept in md rather than internal/secrets so that the
// segmenter and the reveal path can both depend on it without a cycle.
type Directive struct {
	// ID is the secret's stable 12-hex-character id, or "" when absent.
	ID string
	// Visibility is the secret's visibility. It is always one of the three
	// authz.Visibility values; an omitted or unparseable value yields
	// VisibilityPrivate, because the fail-safe direction for a secret is the
	// one nobody but a DM can read.
	Visibility authz.Visibility
	// Author is the username that created the secret, or "" when absent.
	Author string
	// Created is the RFC3339 creation timestamp exactly as written, or "".
	Created string
	// Title is the optional human title, or "".
	Title string
	// BadVisibility records that a visibility= token was present but named a
	// value outside the three known ones. Visibility is then
	// VisibilityPrivate, so a typo in a dm secret redacts harder rather than
	// broadcasting.
	BadVisibility bool
	// HasUnknown records that the info string carried at least one key outside
	// the known set. The segmenter reads that as an unreadable directive and
	// hides the fence, so a directive nothing here could read is not one any
	// reader is shown.
	HasUnknown bool
	// UnknownKeys lists those keys, in the order they appeared.
	UnknownKeys []string
}

// IsSecret reports whether an info string opens a secret fence. It is the
// cheap test the scanner uses before paying for a full parse, and it must
// agree with ParseFenceDirective about where the word ends, so it looks only
// at the first token: a quoted value further along cannot change the answer.
func IsSecret(info string) bool {
	word, _ := splitFirstWord(info)
	return strings.EqualFold(word, SecretFenceWord)
}

// ParseFenceDirective parses a fence info string into a Directive.
//
// The grammar is deliberately small: the word `secret` followed by
// space-separated `key=value` pairs from the known key set. A value may be
// wrapped in matching single or double quotes, which is how a title containing
// a space is written, and the quotes are stripped here.
//
// A key outside the known set is not an error: the parse succeeds and
// HasUnknown is set, because whether a directive nothing here could read may
// be served is the segmenter's decision and not a parse failure. A key
// repeated in the same directive IS an error, since last-one-wins would let a
// directive appear to say one thing and mean another.
func ParseFenceDirective(info string) (Directive, error) {
	fields := scanDirectiveFields([]byte(info), 0)
	if len(fields) == 0 || !strings.EqualFold(string(fields[0].key), SecretFenceWord) {
		return Directive{}, fmt.Errorf("%w: %q", ErrNotSecretFence, info)
	}
	d := Directive{Visibility: authz.VisibilityPrivate}
	seen := map[string]bool{}
	for _, field := range fields[1:] {
		key := strings.ToLower(string(field.key))
		value := string(unquoteBytes(field.value))
		if seen[key] {
			return Directive{}, fmt.Errorf("%w: %q", ErrDuplicateDirectiveKey, key)
		}
		seen[key] = true
		switch key {
		case KeyID:
			d.ID = value
		case KeyVisibility:
			if authz.Visibility(value).Valid() {
				d.Visibility = authz.Visibility(value)
			} else {
				// Redact harder. A typo in a dm secret must not turn it into
				// something readable, and the author finds out from the
				// problem the indexer surfaces rather than from a leak.
				d.Visibility = authz.VisibilityPrivate
				d.BadVisibility = true
			}
		case KeyAuthor:
			d.Author = value
		case KeyCreated:
			d.Created = value
		case KeyTitle:
			d.Title = value
		default:
			d.HasUnknown = true
			d.UnknownKeys = append(d.UnknownKeys, key)
		}
	}
	return d, nil
}

// CreatedTime parses the created timestamp. An absent or malformed value
// yields the zero time; the on-disk text is preserved either way and the
// secrets phase is the only caller that needs a time.Time.
func (d Directive) CreatedTime() time.Time {
	if d.Created == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, d.Created)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ValidVisibility reports whether the directive named a visibility. It is
// false when no visibility= token was present, in which case Visibility holds
// the default of VisibilityPrivate.
func (d Directive) ValidVisibility() bool {
	return !d.BadVisibility && d.Visibility != ""
}

func splitFirstWord(s string) (word, rest string) {
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// directiveField is one `key=value` token of a fence info string, with the
// absolute byte ranges of its key and of its value.
type directiveField struct {
	// key is the field's key, exactly as written.
	key []byte
	// value is the raw value, quotes included. It is nil for a bare key.
	value []byte
	// keyStart and keyEnd bound the key in the document.
	keyStart, keyEnd int
	// valueStart and valueEnd bound the raw value in the document, so a
	// replacement can keep a quoted value's quotes.
	valueStart, valueEnd int
}

// scanDirectiveFields splits a fence info string into its fields.
//
// Quoting is honoured, because a title with a space in it is written
// title="The Vault Door" and a whitespace split reads `Door"` as a key name —
// which is precisely the mistake that once made a reveal rewrite the wrong
// bytes, and then fail to rewrite anything at all.
func scanDirectiveFields(info []byte, base int) []directiveField {
	var out []directiveField
	i := 0
	for i < len(info) {
		for i < len(info) && isSpaceByte(info[i]) {
			i++
		}
		if i >= len(info) {
			break
		}
		f := directiveField{keyStart: base + i}
		for i < len(info) && !isSpaceByte(info[i]) && info[i] != '=' {
			i++
		}
		f.keyEnd = base + i
		f.key = info[f.keyStart-base : f.keyEnd-base]
		if i < len(info) && info[i] == '=' {
			i++
			f.valueStart = base + i
			if i < len(info) && (info[i] == '"' || info[i] == '\'') {
				quote := info[i]
				i++
				for i < len(info) {
					// A backslash escapes whatever follows, so a title that
					// contains its own quote character is one field rather than
					// two. Without it the value ends at that quote and the rest
					// of the line becomes unknown keys, which hides the fence
					// from everybody: a backslash is the only escape this
					// grammar has, so doubling a quote does not work.
					if info[i] == '\\' && i+1 < len(info) {
						i += 2
						continue
					}
					if info[i] == quote {
						i++
						break
					}
					i++
				}
			} else {
				for i < len(info) && !isSpaceByte(info[i]) {
					i++
				}
			}
			f.valueEnd = base + i
			f.value = info[f.valueStart-base : f.valueEnd-base]
		}
		out = append(out, f)
	}
	return out
}

func trimRightSpace(line []byte) []byte {
	end := len(line)
	for end > 0 && isSpaceByte(line[end-1]) {
		end--
	}
	return line[:end]
}

// unquoteBytes strips a quoted value's surrounding quotes and resolves its
// backslash escapes. It is the read side of the quoting that scanDirectiveFields
// writes on the edit side; the two have to agree on where a value ends or a
// reveal would rewrite a range the reader did not recognise as a value.
func unquoteBytes(s []byte) []byte {
	if len(s) < 2 || !(s[0] == '"' && s[len(s)-1] == '"' ||
		s[0] == '\'' && s[len(s)-1] == '\'') {
		return s
	}
	body := s[1 : len(s)-1]
	if bytes.IndexByte(body, '\\') < 0 {
		return body
	}
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) {
			i++
		}
		out = append(out, body[i])
	}
	return out
}
