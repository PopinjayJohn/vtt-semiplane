package secrets

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// Problem codes added by this file. md's own codes describe what the segmenter
// found; these describe what the reader of the fence found afterwards, which is
// a different question and would otherwise have nowhere to live.
const (
	// ProblemDirectiveUnreadable is a fence md classified as secret whose
	// directive line could not be re-read here. The fence is still a secret and
	// is still redacted; only its metadata is unavailable, so it falls back to
	// the fail-safe private visibility with no author.
	ProblemDirectiveUnreadable = "secret.directive_unreadable"
	// ProblemAuthorUnknown is a directive naming an author= that is not a known
	// account. The secret is not indexed rather than indexed with a fabricated
	// author, because secrets.author_id is a foreign key and "somebody" is not
	// a user. The fence stays secret on disk; what is lost is the secret's
	// presence in the index, which is a miss rather than a leak.
	ProblemAuthorUnknown = "secret.author_unknown"
)

// Parse returns every ```secret fence a document holds, in file order, together
// with the document's own parse problems.
//
// It is the bridge between md's byte-level segmentation and everything that
// wants a fence as a value. md owns the parse of the directive — there is one
// implementation of the key set and it is md.ParseFenceDirective, because two
// implementations of a closed grammar drift, and the drift shows up as a secret
// rendered in plaintext. This file owns what happens above it: the body, the
// hash, the offsets and the visibility a fence claims.
//
// The body is plaintext. Nothing in this package may put one into an error, a
// log record or an event payload; the hash is what travels.
func Parse(d *md.Doc) ([]Secret, []md.Problem) {
	if d == nil {
		return nil, nil
	}
	problems := d.Problems
	spans := d.SecretSpans()
	out := make([]Secret, 0, len(spans))

	for i, raw := range spans {
		s := clampSpan(d.Bytes, raw)
		sec := Secret{
			ID:      s.SecretID,
			Ordinal: i,
			// The fail-safe default. A fence whose directive cannot be read
			// keeps the visibility nobody but a DM can see, because the failure
			// mode of guessing wrong in the other direction is a secret rendered
			// to the table.
			Visibility: VisibilityPrivate,
			StartByte:  s.StartByte,
			EndByte:    s.EndByte,
		}
		line, bodyStart := fenceLine(d.Bytes, s)
		sec.Directive = string(line)

		info, ok := directiveInfo(line)
		if ok {
			dir, err := md.ParseFenceDirective(info)
			switch {
			case err != nil:
				problems = append(problems, unreadable(s))
			case dir.HasUnknown:
				// md demotes such a fence to public passthrough, so it is not a
				// secret span at all and cannot reach this loop. Arriving here
				// means the two halves of md disagree, which is reported rather
				// than trusted: an unknown key is a directive whose meaning this
				// package cannot claim to have enforced.
				problems = append(problems, unreadable(s))
			default:
				sec.Visibility = dir.Visibility
				sec.Author = dir.Author
				sec.Title = dir.Title
				sec.CreatedAt = dir.CreatedTime()
			}
		} else {
			problems = append(problems, unreadable(s))
		}

		body := md.SecretBody(d.Bytes, s)
		sec.Body = string(body)
		sec.BodyHash = vault.Hash(body)
		sec.BodyStartByte = bodyStart
		sec.BodyEndByte = bodyStart + len(body)
		out = append(out, sec)
	}
	return out, problems
}

// clampSpan puts a span inside the document it claims to index.
//
// A span from md.Parse is inside the buffer by construction, but this function
// takes a *md.Doc from a caller and md's own accessors index the buffer with the
// span's end offset without checking it. A single out-of-range span is therefore
// a panic, and a panic in the indexer is a crash of the whole application on a
// file the DM did not write. Clamping costs three comparisons and turns any such
// span into an empty fence, which is redacted and indexed as nothing.
func clampSpan(src []byte, s md.Span) md.Span {
	start := s.StartByte
	if start < 0 {
		start = 0
	}
	if start > len(src) {
		start = len(src)
	}
	end := s.EndByte
	if end > len(src) {
		end = len(src)
	}
	if end < start {
		end = start
	}
	s.StartByte, s.EndByte = start, end
	return s
}

func unreadable(s md.Span) md.Problem {
	return md.Problem{
		Code:      ProblemDirectiveUnreadable,
		StartByte: s.StartByte,
		SecretID:  s.SecretID,
		Message:   "secret fence directive could not be read back",
	}
}

// SecretIDLength is the length of a secret id on disk.
//
// The format is fixed — twelve lowercase hex characters — because the id travels
// in a URL, in a DOM handle, in an audit row and in the fence directive itself,
// and every one of those wants the same short opaque token. A fence that does not
// have one is malformed, and md substitutes a placeholder so that its span can
// still be attributed; a placeholder must never be written to the index, because
// naming it in a reveal would look for a fence whose directive says something
// else.
const SecretIDLength = 12

// ValidSecretID reports whether an id is the twelve lowercase hex characters the
// on-disk format specifies.
func ValidSecretID(id string) bool {
	if len(id) != SecretIDLength {
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

// Valid reports whether the fence carries everything the index needs: a
// conforming id, a known visibility and a body hash. A fence that fails is
// redacted on screen and absent from the index, which is the direction that
// leaks nothing.
func (s Secret) Valid() bool {
	return ValidSecretID(s.ID) && s.Visibility.Valid() && len(s.BodyHash) == sha256.Size
}

// String describes the fence without its body, for an error or a log line.
func (s Secret) String() string {
	return fmt.Sprintf("secret %s at ordinal %d, %s, %d body bytes",
		s.ID, s.Ordinal, s.Visibility, len(s.Body))
}

// fenceLine returns the bytes of a secret span's opening line without its
// terminator, and the offset of the first byte after that line.
//
// The span starts at the opening fence, so the line is bounded by the span: a
// scan that ran past the end of the span would be looking for a newline the
// caller has already told us is not there. When the fence is unterminated the
// body starts at the end of the span, which is where md puts it too.
func fenceLine(src []byte, s md.Span) (line []byte, next int) {
	from := s.StartByte
	if from < 0 || from >= len(src) {
		return nil, from
	}
	to := s.EndByte
	if to > len(src) {
		to = len(src)
	}
	if to <= from {
		return nil, from
	}
	i := bytes.IndexByte(src[from:to], '\n')
	if i < 0 {
		return src[from:to], to
	}
	to = from + i
	// The CR of a CRLF terminator belongs to the line, not to the directive.
	if to > from && src[to-1] == '\r' {
		to--
	}
	return src[from:to], from + i + 1
}

// directiveInfo returns the info string of a fence opening line: the bytes after
// the fence run, with the trailing whitespace removed.
//
// It re-derives only the front of the line. md has already classified the line
// as a secret fence, so this is not a second fence parser and cannot disagree
// about what a fence is; it is the handful of bytes between the backticks and
// the directive, and it refuses anything that is not a secret directive rather
// than returning a half-read one.
func directiveInfo(line []byte) (string, bool) {
	i := 0
	// Block-quote markers and indentation, in the order CommonMark reads them:
	// a fence inside a quote is still a fence.
	for i < len(line) {
		j := i
		for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
			j++
		}
		if j < len(line) && line[j] == '>' {
			i = j + 1
			if i < len(line) && (line[i] == ' ' || line[i] == '\t') {
				i++
			}
			continue
		}
		i = j
		break
	}
	if i >= len(line) {
		return "", false
	}
	c := line[i]
	if c != '`' && c != '~' {
		return "", false
	}
	// The cursor must advance past the run, or a line of a hundred backticks
	// would re-read the same byte a hundred times.
	run := 0
	for i+run < len(line) && line[i+run] == c {
		run++
	}
	if run < 3 {
		return "", false
	}
	i += run
	info := strings.TrimRight(string(line[i:]), " \t\r")
	if !md.IsSecret(info) {
		return "", false
	}
	return info, true
}
