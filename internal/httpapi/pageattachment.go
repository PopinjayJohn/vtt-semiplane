package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// §8.8's serve path, page-scoped.
//
// There is deliberately no global /attachments/{name} route, and the reason is
// the rule this file implements: a file referenced only from inside a secret is
// served only to principals who may read that secret. A global route would have
// to answer that question without knowing which page a name came from, and the
// only answer it could give is "yes", which hands a DM's portrait to anybody
// who can guess its filename.

// attachmentCSP is the policy every attachment response carries.
//
// It replaces the app's own on this route, and it is not a stricter copy: the
// app's policy is `default-src 'self'`, and an attachment is content this app
// does not vouch for — it is a file somebody dropped in the vault, and a .html
// one served from the app's own origin with the app's own script available to
// it would be stored XSS with a content-type the browser has no reason to
// doubt. So nothing loads, and `sandbox` puts the response in an opaque origin
// with no scripts even for a document the browser would otherwise treat as
// first-party. `default-src 'none'` and no allowlist is the whole policy; a
// future image added to it has to be argued for, not defaulted to.
const attachmentCSP = "default-src 'none'; sandbox"

// maxAttachmentBytes is the largest file this route serves.
//
// vault.Read already refuses anything over MaxFileBytes, so this is not the
// binding limit; it exists so that the response's size is bounded by something
// this route states rather than by something it inherits, and so that a file
// that somehow reached that size is a failure this route names instead of a
// multi-megabyte answer to a GET.
const maxAttachmentBytes = 16 << 20

// attachment answers GET /p/*/attachment/{name...}.
func (s *Server) attachment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)
	row, ok := s.readablePage(w, r, ctx)
	if !ok {
		return
	}
	name, ok := attachmentName(selectedParam(r, "name"))
	if !ok {
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	// The name is compared exactly, never by basename and never after being
	// resolved, so a name that escapes the vault cannot match a recorded path
	// and is refused before the filesystem is touched at all. Resolve is below
	// as a second line, not as the first: the store is what decides the name is
	// one of this page's files, and a path-traversal attempt that never got
	// that far must not be able to tell by the answer whether it was close.
	visible, err := store.AttachmentVisibleTo(ctx, s.db.Reader(), who, row.ID, name)
	if err != nil {
		s.fail(w, r, "check the attachment's visibility", err)
		return
	}
	if !visible {
		// "You may not have it" and "there is no such file" are one answer,
		// because a route that could tell them apart is a route that confirms
		// the existence of a DM's portrait.
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	// The recorded row, found through the page rather than through the path.
	//
	// store.GetAttachmentByPath would be one point lookup instead, and it is
	// wrong: a file referenced from two pages has one attachments row per page
	// and one shared path, so a lookup by path returns whichever row came first
	// and a page that is not the first is then answered 404 for a file the
	// visibility check above just said it may have. Asking for this page's rows
	// and matching the name among them is the only lookup that cannot pick the
	// wrong page, and the list is the number of files on one page.
	att, err := s.attachmentRowFor(ctx, row.ID, name)
	if err != nil {
		s.fail(w, r, "read the attachment's index row", err)
		return
	}
	if att.Path == "" {
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	p, err := vault.Resolve(s.root, att.Path)
	if err != nil {
		s.log.WarnContext(ctx, "a recorded attachment did not resolve inside the vault",
			"action", "http.attachment", "route", RouteFrom(ctx), "page", row.Path)
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	src, err := vault.Read(ctx, p)
	if err != nil {
		if isMissing(err) {
			s.writeError(w, r, http.StatusNotFound)
			return
		}
		s.fail(w, r, "read the attachment", err)
		return
	}
	if len(src) > maxAttachmentBytes {
		s.fail(w, r, "serve the attachment", errTooLarge(p.Rel()))
		return
	}

	h := w.Header()
	h.Set("Content-Security-Policy", attachmentCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	// Authorization-dependent, and the file itself is a page's private content,
	// so it is not stored anywhere at all rather than kept fresh.
	s.noStore(w)
	if ct := att.Mime; ct != "" {
		h.Set("Content-Type", ct)
	}
	h.Set("Content-Length", strconv.Itoa(len(src)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(src)
}

// attachmentRowFor is the recorded row for one of a page's attachments, or the
// zero value when the page has no such row.
//
// The zero value answers "not found" through an empty Path rather than through a
// bool, so the caller has exactly one thing to test and a store failure is a
// store failure rather than a 404.
func (s *Server) attachmentRowFor(ctx context.Context, pageID int64, name string) (store.Attachment, error) {
	rows, err := store.ListAttachmentsByPage(ctx, s.db.Reader(), pageID)
	if err != nil {
		return store.Attachment{}, err
	}
	for _, a := range rows {
		if a.Path == name {
			return a, nil
		}
	}
	return store.Attachment{}, nil
}

// attachmentName is the one name this route will serve, or false.
//
// A name is refused for four reasons and each is a property of the name rather
// than of the file it might name, so all four are decided before anything is
// read:
//
//   - it is empty, or is only separators;
//   - it is absolute, or names a Windows drive;
//   - any segment is "." or "..";
//   - it contains a backslash or a NUL.
//
// store.AttachmentVisibleTo already refuses all of them, because it matches the
// name against a recorded path and no recorded path is any of those. This is the
// second line, and the reason for having it is that the check is a fixed-size
// decision made from one string: a caller that later loosened the store's match
// — a basename comparison, say — would not be loosening it here.
func attachmentName(name string) (string, bool) {
	if name == "" || len(name) > 1024 {
		return "", false
	}
	if strings.ContainsAny(name, "\\\x00") {
		return "", false
	}
	if strings.HasPrefix(name, "/") {
		return "", false
	}
	// A drive-letter path, for the case where a vault is on Windows and the
	// resolved path would be absolute again after Join.
	if len(name) >= 2 && name[1] == ':' {
		return "", false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return "", false
		}
	}
	return name, true
}

// isMissing reports whether an error is vault's "there is no such file".
func isMissing(err error) bool { return errors.Is(err, vault.ErrNotFound) }

// errTooLarge is the error a file over this route's cap produces.
//
// It is a type rather than a format so that the message cannot acquire a second
// value by accident, and so that the one field in it is a path — a path is safe
// in a log line, which a byte of a file is not.
func errTooLarge(rel string) error {
	return &tooLargeError{rel: rel}
}

// tooLargeError is a file this route will not serve.
type tooLargeError struct {
	rel string
}

func (e *tooLargeError) Error() string {
	return "the file " + e.rel + " is over the " + strconv.Itoa(maxAttachmentBytes) + " byte serve limit"
}
