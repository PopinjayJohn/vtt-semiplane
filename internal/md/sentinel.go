package md

import (
	"bytes"
	"crypto/sha256"
	hexenc "encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// The redacted editor's sentinel: what an unreadable secret's body becomes in
// the editor buffer, and what puts the original bytes back on save.
//
// A sentinel is a restore token, not an obfuscation. It carries nothing that was
// in the secret — the id is already on the fence line, and the digest of a body
// the reader may not read is not a disclosure of the body — and everything needed
// to prove that the body came back unmodified. What it deliberately does not do
// is describe the body: the length and the digest are a fingerprint, so a buffer
// holding one is a fixed size whatever the secret says, and the body itself never
// reaches a page the reader may not open.
const (
	// sentinelOpen is U+2039 SINGLE LEFT-POINTING ANGLE QUOTATION MARK.
	sentinelOpen = "\u2039"
	// sentinelClose is U+203A SINGLE RIGHT-POINTING ANGLE QUOTATION MARK.
	sentinelClose = "\u203a"
	// sentinelTag is the literal that opens every sentinel, so a reader of a
	// buffer can tell a sentinel from ordinary text without parsing it.
	sentinelTag = "s"
	// sentinelHashBytes is how much of the body digest a sentinel carries: the
	// first four bytes, eight hex characters. Eight is enough that an accidental
	// collision between two different bodies of different lengths is not a thing
	// anybody has to reason about, and short enough that the token reads as a
	// token.
	sentinelHashBytes = 4
	// secretIDHexLen is the length of an on-disk secret id: twelve lowercase hex
	// characters. It is spelled here rather than imported from internal/secrets
	// because that package sits above this one in the dependency order, and two
	// definitions of the on-disk id format is one more thing that can disagree
	// with the file.
	secretIDHexLen = 12
	// unaddressableBody replaces a hidden secret's body when the secret has no
	// id a sentinel can carry — a fence whose directive could not be read, for
	// which the segmenter substitutes a placeholder. The body is replaced
	// anyway, because passing the body through would be the leak, and the
	// placeholder is deliberately not a valid sentinel, so a save of that page
	// is refused rather than silently losing the body.
	unaddressableBody = sentinelOpen + "redacted" + sentinelClose
)

// Problem codes reported by the redacted save path. They are distinct codes
// rather than one "bad sentinel" because the caller renders a different message
// for each: a stale editor and a forged one are not the same event, and an
// author who typed over a hidden secret needs to be told that rather than that
// something is malformed.
const (
	// ProblemSentinelUnknown is a sentinel naming a secret the file does not
	// hold. It is a stale editor or a forgery, and neither may restore a body.
	ProblemSentinelUnknown = "secret.sentinel_unknown"
	// ProblemSentinelMismatch is a fence whose body is a sentinel for a
	// different secret than the fence names. A sentinel is only ever rendered
	// into its own fence, so the two disagreeing means the buffer was built by
	// something other than this package's redaction.
	ProblemSentinelMismatch = "secret.sentinel_mismatch"
	// ProblemSentinelModified is a sentinel whose length or digest is not the
	// one the current on-disk body has. The user changed something they may not
	// read, so nothing is written.
	ProblemSentinelModified = "secret.sentinel_modified"
	// ProblemSentinelAuthored is a hidden secret whose body is real text. The
	// user replaced a body they may not read, which is a different and
	// separately authorised operation from editing the public text around it.
	ProblemSentinelAuthored = "secret.sentinel_authored"
	// ProblemSentinelDuplicated is a hidden secret's id claimed by more than
	// one fence in the submission. The bytes would be restored into both, which
	// is not a state the file can be in.
	ProblemSentinelDuplicated = "secret.sentinel_duplicated"
	// ProblemSecretBlockRemoved is a hidden secret with no fence at all in the
	// submission. Deleting a whole block is permitted and separately
	// authorised; deleting it by editing this buffer is not.
	ProblemSecretBlockRemoved = "secret.block_removed"
)

// Errors returned by Splice, as distinct from the problems it reports. A
// problem names a byte range and a secret, so the caller can show it to the
// author; these two say the inputs cannot be reasoned about at all.
var (
	// ErrNoDocument reports a nil document.
	ErrNoDocument = errors.New("md: no document")
	// ErrDuplicateSecretID reports a file holding two fences with the same id.
	// Which of them a sentinel restores is then a guess, and a guess here writes
	// one secret's body where the other was.
	ErrDuplicateSecretID = errors.New("md: two secret fences share one id")
)

// SentinelBody is a sentinel read back out of a buffer. It carries the three
// facts the save path checks the on-disk body against, and nothing else: the
// body itself is not in it, in either direction.
type SentinelBody struct {
	// ID is the secret the sentinel restores.
	ID string
	// Len is the length in bytes of the body the sentinel was rendered from.
	Len int
	// Hash is the first eight lowercase hex characters of that body's sha256.
	Hash string
}

// Matches reports whether body is the one this sentinel was rendered from. It is
// the check that makes a sentinel unforgeable in the only direction that
// matters: a user who cannot read the body cannot produce its digest, and one
// who guesses wrong is refused rather than believed.
func (s SentinelBody) Matches(body []byte) bool {
	return s.Len == len(body) && s.Hash == digestPrefix(body)
}

// Sentinel renders the token that stands in for a secret's body in an editor
// buffer: ‹s:<id>:<bodyLen>:<bodySHA256first8>›. An id that is not a valid
// on-disk secret id renders as the empty string, because a token that named a
// placeholder or an unparsed directive could be spliced back into a fence the
// file does not have.
//
// body is the body exactly as SecretBody returns it, including the line
// terminator that ends the last body line, because that is the byte range
// internal/secrets hashes into a Secret.BodyHash. The digest here is the plain
// sha256 of the same bytes, so the two agree by construction; a sentinel whose
// body were the terminator-stripped content would hash something nothing else in
// the app has ever hashed, and a disagreement between the two would refuse every
// redacted save on the page for a reason nobody could see.
func Sentinel(id string, body []byte) string {
	if !validSecretID(id) {
		return ""
	}
	var b []byte
	b = append(b, sentinelOpen...)
	b = append(b, sentinelTag...)
	b = append(b, ':')
	b = append(b, id...)
	b = append(b, ':')
	b = strconv.AppendInt(b, int64(len(body)), 10)
	b = append(b, ':')
	b = append(b, digestPrefix(body)...)
	b = append(b, sentinelClose...)
	return string(b)
}

// ParseSentinel recognises a body that is exactly one sentinel and nothing else.
// A body that merely contains sentinel-shaped text is not a sentinel: the only
// way this is called is on a secret's body as the segmenter found it, and a
// secret whose author wrote ‹s:…› as prose is prose, not a restore token.
//
// The grammar is closed on purpose. Uppercase hex, a leading zero on the length
// and a trailing byte of any kind are all refused, so every sentinel in every
// buffer has exactly one spelling and a tampered one cannot pass for a second
// valid form of the original.
func ParseSentinel(body []byte) (SentinelBody, bool) {
	var out SentinelBody
	raw, ok := bytes.CutPrefix(body, []byte(sentinelOpen+sentinelTag+":"))
	if !ok {
		return out, false
	}
	raw, ok = bytes.CutSuffix(raw, []byte(sentinelClose))
	if !ok {
		return out, false
	}
	fields := bytes.Split(raw, []byte(":"))
	if len(fields) != 3 {
		return out, false
	}
	if !validSecretID(string(fields[0])) || !validHash(string(fields[2])) {
		return out, false
	}
	n, err := strconv.Atoi(string(fields[1]))
	// A length is a count of bytes, so it is never negative and never written
	// with a leading zero: one spelling per body keeps the grammar closed.
	if err != nil || n < 0 || (n > 0 && fields[1][0] == '0') {
		return out, false
	}
	return SentinelBody{ID: string(fields[0]), Len: n, Hash: string(fields[2])}, true
}

// Redact returns the document's bytes with the body of every secret whose id is
// in hidden replaced by its sentinel, or the document's own bytes when nothing
// is hidden.
//
// Only the body goes. The fence line carries the id, the author, the timestamp
// and the title, and it stays, because a redacted editor that hid the fence would
// leave a user with no way to see that the page has a secret on it at all, and
// §8.9's whole point is that the public parts of a page stay editable.
//
// The replacement keeps the body's own line terminator, so the closing fence
// stays on its own line and the redacted buffer re-parses into the same spans the
// file had. That is what makes the round trip byte-exact rather than merely
// close, and it is why the body is split before it is replaced instead of being
// replaced whole.
//
// A body with no room for a sentinel is left as it is, and there is only one
// such shape: a file whose last line is a secret fence, with no line terminator
// after it and no body. A sentinel written there would sit on the fence's own
// line, and the `id=` value is an unquoted run to the end of the line, so the
// buffer would re-parse as a document holding a secret called
// `000000000000‹s:000000000000:0:…›`. The body is empty, so nothing is
// disclosed by leaving it; the save path treats an empty body in the submission
// as nothing that could have been edited, which is what it is.
func Redact(d *Doc, hidden map[string]bool) []byte {
	if d == nil || len(hidden) == 0 {
		return docBytes(d)
	}
	var edits []spliceEdit
	for _, s := range d.SecretSpans() {
		if !hidden[s.SecretID] {
			continue
		}
		start, end := secretBody(d.Bytes, s)
		if start < 0 || start > end || end > len(d.Bytes) {
			continue
		}
		if start == end && (start == 0 || d.Bytes[start-1] != '\n') {
			continue
		}
		_, tail := splitTerminator(d.Bytes[start:end])
		if len(tail) == 0 {
			tail = []byte("\n")
		}
		token := Sentinel(s.SecretID, d.Bytes[start:end])
		if token == "" {
			token = unaddressableBody
		}
		edits = append(edits, spliceEdit{
			Start: start,
			End:   end,
			With:  append([]byte(token), tail...),
		})
	}
	// Back to front, so that the offsets of the edits not yet applied stay
	// valid. The same discipline SetVisibility uses, for the same reason.
	out := d.Bytes
	for i := len(edits) - 1; i >= 0; i-- {
		out = splice(out, edits[i].Start, edits[i].End, edits[i].With)
	}
	return out
}

// Splice rebuilds a submitted editor buffer as the file to write, restoring the
// body of every secret the reader was not allowed to see.
//
// It walks the submitted buffer's own secret spans, never the buffer's text: a
// sentinel is recognised by position against the set of secrets the file
// actually holds, so a secret body that itself contains ‹s:…› is restored as
// bytes and a public region that happens to hold the same characters is never
// looked at. A scan for sentinel-shaped text would be a different function with
// a different answer, and the difference is a body that can never be restored or
// a region that can be rewritten on the strength of a coincidence.
//
// Every problem refuses the whole save and returns d.Bytes. A partial write is
// not a smaller version of this operation, it is a file whose secrets and public
// text came from two different documents. The caller decides what each problem
// means: a user who may not read a secret cannot change one, but a user who may
// is simply editing, and that caller's hidden set is empty.
//
// StartByte on a returned problem is an offset into the submitted buffer for a
// problem about something in it, and into d.Bytes for a secret the submission
// does not have at all.
func Splice(d *Doc, submitted []byte, hidden map[string]bool) ([]byte, []Problem, error) {
	if d == nil {
		return nil, nil, ErrNoDocument
	}
	if len(hidden) == 0 {
		return submitted, nil, nil
	}
	known, err := onDiskSecrets(d)
	if err != nil {
		return d.Bytes, nil, err
	}

	sub := Parse(d.Path, submitted)
	var problems []Problem
	var edits []spliceEdit
	claimed := map[string]int{}
	for _, s := range sub.SecretSpans() {
		content, _ := splitTerminator(SecretBody(sub.Bytes, s))
		token, isSentinel := ParseSentinel(content)
		if isSentinel {
			on, exists := known[token.ID]
			if !exists {
				problems = append(problems, Problem{
					Code:      ProblemSentinelUnknown,
					StartByte: s.StartByte,
					SecretID:  token.ID,
					Message:   "a sentinel names a secret this page does not hold",
				})
				continue
			}
			if token.ID != s.SecretID {
				problems = append(problems, Problem{
					Code:      ProblemSentinelMismatch,
					StartByte: s.StartByte,
					SecretID:  token.ID,
					Message:   "a sentinel is in a fence that names a different secret",
				})
				continue
			}
			if !hidden[token.ID] {
				// The reader may read this one, so the text in the buffer is
				// theirs and nothing is restored over it.
				continue
			}
			claimed[token.ID]++
			if claimed[token.ID] > 1 {
				problems = append(problems, Problem{
					Code:      ProblemSentinelDuplicated,
					StartByte: s.StartByte,
					SecretID:  token.ID,
					Message:   "a secret appears in more than one fence in the submission",
				})
				continue
			}
			if !token.Matches(on.body) {
				problems = append(problems, Problem{
					Code:      ProblemSentinelModified,
					StartByte: s.StartByte,
					SecretID:  token.ID,
					Message:   "a secret the reader may not see was changed in the buffer",
				})
				continue
			}
			// The whole submitted body range is replaced, terminator included,
			// so the file gets back the bytes it had. Anything the editor did
			// to the line ending around the sentinel — a browser textarea
			// rewrites CRLF as LF on submit — is inside a region the reader is
			// not allowed to edit, and comes back as it was rather than
			// becoming a refused save.
			start, end := secretBody(sub.Bytes, s)
			if start < 0 || start > end || end > len(sub.Bytes) {
				continue
			}
			edits = append(edits, spliceEdit{Start: start, End: end, With: on.body})
			continue
		}

		if !hidden[s.SecretID] {
			continue
		}
		claimed[s.SecretID]++
		if claimed[s.SecretID] > 1 {
			problems = append(problems, Problem{
				Code:      ProblemSentinelDuplicated,
				StartByte: s.StartByte,
				SecretID:  s.SecretID,
				Message:   "a secret appears in more than one fence in the submission",
			})
			continue
		}
		if len(content) == 0 && len(known[s.SecretID].body) == 0 {
			// An empty body in the submission and an empty body on disk are
			// the same bytes, so there is nothing that could have been edited
			// and nothing to report.
			continue
		}
		problems = append(problems, Problem{
			Code:      ProblemSentinelAuthored,
			StartByte: s.StartByte,
			SecretID:  s.SecretID,
			Message:   "a secret the reader may not see has text in the buffer",
		})
	}

	for _, id := range sortedKeys(hidden) {
		if _, ok := known[id]; !ok {
			// A hidden id the file does not hold names a secret the reader was
			// never shown, so there is nothing in the buffer to be missing.
			continue
		}
		if claimed[id] == 0 {
			problems = append(problems, Problem{
				Code:      ProblemSecretBlockRemoved,
				StartByte: known[id].span.StartByte,
				SecretID:  id,
				Message:   "a secret the reader may not see is missing from the submission",
			})
		}
	}

	if len(problems) > 0 {
		return d.Bytes, problems, nil
	}
	out := submitted
	// Back to front: the submitted document's spans are in ascending order, so
	// the last edit is the last one in the file and the offsets of the rest are
	// still the ones they were.
	for i := len(edits) - 1; i >= 0; i-- {
		out = splice(out, edits[i].Start, edits[i].End, edits[i].With)
	}
	return out, nil, nil
}

// onDiskSecret is one fence as the file currently has it: the span, and the body
// bytes a sentinel for it has to match.
type onDiskSecret struct {
	span Span
	body []byte
}

// onDiskSecrets indexes the file's own secrets by id. Two fences sharing an id
// is an error rather than a last-one-wins, because a sentinel restores a body
// and there would be no way to say which of the two it belongs in.
func onDiskSecrets(d *Doc) (map[string]onDiskSecret, error) {
	out := make(map[string]onDiskSecret, len(d.SecretSpans()))
	for _, s := range d.SecretSpans() {
		if _, dup := out[s.SecretID]; dup {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateSecretID, s.SecretID)
		}
		out[s.SecretID] = onDiskSecret{span: s, body: SecretBody(d.Bytes, s)}
	}
	return out, nil
}

// splitTerminator separates a body's last line terminator from its content.
//
// The terminator belongs to the line, not to the body, and the two have to be
// told apart in both directions: redaction leaves the terminator where it was so
// the closing fence stays on its own line, and the save path looks for the
// sentinel in what is left. A body that is all terminators has no content at
// all, which is the state the round trip has to preserve exactly.
func splitTerminator(body []byte) (content, terminator []byte) {
	end := len(body)
	for end > 0 && (body[end-1] == '\n' || body[end-1] == '\r') {
		end--
	}
	return body[:end], body[end:]
}

// digestPrefix is the leading slice of a body's sha256 as lowercase hex. It is
// the same digest internal/vault.Hash computes, written out here because this
// package sits below vault and a sentinel cannot wait on an import cycle to know
// how a body is fingerprinted.
func digestPrefix(body []byte) string {
	sum := sha256.Sum256(body)
	return hexenc.EncodeToString(sum[:sentinelHashBytes])
}

// validSecretID reports the on-disk id shape: twelve lowercase hex characters.
// It is the same rule internal/secrets.ValidSecretID applies, and the reason a
// sentinel for a placeholder id cannot be rendered is that a placeholder was
// never an id — naming one in a restore token would make a fence that could not
// be parsed addressable as though it could.
func validSecretID(id string) bool {
	if len(id) != secretIDHexLen {
		return false
	}
	for i := range len(id) {
		c := id[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// validHash reports the digest half of a sentinel: eight lowercase hex
// characters, written lowercase by Sentinel and compared exactly, so a
// capitalised digest is a tampered token rather than a second spelling.
func validHash(h string) bool {
	if len(h) != sentinelHashBytes*2 {
		return false
	}
	for i := range len(h) {
		c := h[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

func docBytes(d *Doc) []byte {
	if d == nil {
		return nil
	}
	return d.Bytes
}
