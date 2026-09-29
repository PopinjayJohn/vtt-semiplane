package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// Reveal and revoke, §8.3, as HTTP.
//
// Both rows are the same handler with a different service call, and they are one
// handler because they are one operation: `reveal` is `visibility=table` and
// `revoke` is `visibility=private`, and every property either of them has — who
// may ask, what a refused principal learns, what a lost race looks like — is a
// property of the pair and would be a second copy to keep in step if they were
// two.
//
// **This file decides nothing.** The permission, the byte-surgical rewrite, the
// audit row, the generation bump and the reindex all live in
// secrets.Service.SetVisibility, which asks authz.Policy for PermDM before it
// looks anything up. Re-deciding any of it here would be a second implementation
// of a rule the service already owns, and a handler that disagrees with the
// service is a handler whose gate is the one that can be wrong.
//
// **The response carries no body, and that is the point.** A reveal is a state
// change whose answer is a redirect; the plaintext arrives on the next GET,
// through the ordinary page render, under the requester's own principal. This is
// the same rule the live-push stream obeys — a trigger, never content
// (events.go) — and it is why there is no second path here by which a revealed
// body could be read out of a POST.

// secretVisibility is one direction of the one operation both rows are.
type secretVisibility struct {
	// action is the word this file logs the event under, so that a line in the
	// request log says "reveal" or "revoke" and not "POST", and the two directions
	// of one operation are greppable apart.
	//
	// It is not passed to the service: the service names its own events, in
	// secret_events and in its own log lines, and a second vocabulary here would be
	// a second answer to "what was this row called".
	action string
	// apply is the service call. It is a field rather than a switch here because
	// the switch would be a second place naming what a reveal and a revoke are.
	apply func(*secrets.Service, context.Context, authz.Principal, string) error
}

// revealSecret answers POST /p/*/secrets/{secretID}/reveal.
func (s *Server) revealSecret(w http.ResponseWriter, r *http.Request) {
	s.setSecretVisibility(w, r, secretVisibility{action: "reveal", apply: (*secrets.Service).Reveal})
}

// revokeSecret answers POST /p/*/secrets/{secretID}/revoke.
func (s *Server) revokeSecret(w http.ResponseWriter, r *http.Request) {
	s.setSecretVisibility(w, r, secretVisibility{action: "revoke", apply: (*secrets.Service).Revoke})
}

// setSecretVisibility is both handlers.
//
// The order is the authorization order every page-scoped surface in this package
// uses, and each step exists for one reason. The page is resolved first, so a
// path that names nothing is a 404 and not a write; the secret is resolved
// second, against *this principal's* visibility, so an id this reader may not
// read and an id that was never issued are the same value; and only then is the
// service called. A handler that called the service first would let the service's
// own policy answer for a page that does not exist, and the two 404s would then
// not be the same 404.
//
// A successful change answers 303 to the page, as a revert does. It is a redirect
// rather than a re-render because the reader asked to change a fence, the page is
// what they want to see afterwards, and a redirect cannot carry a body at all — so
// there is no way for a revealed body to be attached to one by accident.
func (s *Server) setSecretVisibility(w http.ResponseWriter, r *http.Request, change secretVisibility) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)

	// readablePage, not writablePage: ownership buys the right to author a secret
	// and never the right to broadcast one, so this route is not the editor's and
	// must not answer with the editor's 403.
	row, ok := s.readablePage(w, r, ctx)
	if !ok {
		return
	}
	secretID := strings.TrimSpace(selectedParam(r, "secretID"))
	if secretID == "" {
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	// Before the write, not after. A secret this principal may not read is
	// answered as a page that has no such secret, which is one value from one
	// query rather than two statuses chosen here.
	carries, err := s.pageCarriesSecret(ctx, who, row.ID, secretID)
	if err != nil {
		s.fail(w, r, "read the page's secrets", err)
		return
	}
	if !carries {
		// writeError and not a status of this package's own, for the reason
		// AGENTS.md §7 gives: the body has to be byte-identical to the body for a
		// secret that is not there and to the body for a page that is not there,
		// and the only way to guarantee two renderings are identical is for the
		// error model to hold nothing that could differ between them.
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	err = change.apply(s.secrets, ctx, who, secretID)
	switch {
	case err == nil:
		s.log.InfoContext(ctx, "a secret's visibility was changed through the app",
			"action", "http.secret", "route", RouteFrom(ctx),
			"path", row.Path, "what", change.action, "actor_id", who.UserID, "secret_id", secretID)
		http.Redirect(w, r, cardOf(row).Href(), http.StatusSeeOther)
	case errors.Is(err, store.ErrNoRows), errors.Is(err, secrets.ErrNotInFile):
		// An id the index no longer has, and a fence the file no longer has, are
		// both "there is nothing here". The second is a real state — the page was
		// rewritten without the fence between the index and this call — and
		// reporting it as anything else would tell a reader that a secret they may
		// not read exists and has been deleted.
		s.writeError(w, r, http.StatusNotFound)
	case errors.Is(err, vault.ErrConflict):
		// A lost optimistic-concurrency race. The status is the editor's 409 and
		// the copy is the editor's 409 copy — "the file changed on disk before
		// this was written, so nothing was changed" — because that sentence is
		// exactly what happened and it carries no merge.
		//
		// It is deliberately NOT s.answerConflict, and the reason is worth
		// recording because it is the opposite of the obvious answer. The
		// conflict *view* is a merge: it diffs the file against a submitted
		// buffer and posts a per-hunk resolution to the editor. A reveal submits
		// no buffer, so that page would diff the whole file against nothing and
		// offer a "Write the resolved file" button whose submission is an empty
		// document — a control that empties the page on click, on a page that
		// holds a DM's secrets. A 409 with fixed copy is a smaller answer, and a
		// smaller answer that cannot destroy anything is the right one.
		//
		// RaceLostError carries no bytes — see its own doc comment in
		// internal/secrets — so nothing about the file that lost the race reaches
		// the response through this path either.
		s.writeError(w, r, http.StatusConflict)
	case isDenial(err):
		// The table's gate refused first for every principal the policy refuses,
		// so reaching here means a caller reached the service without it. It is
		// 403 and not 500 because a refused write and a broken server are
		// different events and only one of them is the operator's problem.
		s.log.WarnContext(ctx, "a secret's visibility change was refused by the policy",
			"action", "http.secret", "route", RouteFrom(ctx), "path", row.Path, "what", change.action)
		s.writeError(w, r, http.StatusForbidden)
	default:
		s.fail(w, r, change.action+" the secret", err)
	}
}

// pageCarriesSecret reports whether the page's own fence list holds this id, as
// filtered for this principal.
//
// The list is the secrets service's ListPage rather than a second call into
// store, because that is the query that carries authz.SecretVisibleSQL verbatim.
// A page owner asking about a `dm` fence is answered "this page has no such
// secret", which is the same answer as an id nobody ever issued — and that
// indistinguishability is the entire security property of these two routes.
//
// The cost is that it is a list rather than a lookup: the page's fences are read
// and one of them is compared. A page holds a handful and the list carries no
// bodies, so the alternative would be a store query this package may not add.
func (s *Server) pageCarriesSecret(ctx context.Context, who authz.Principal, pageID int64, secretID string) (bool, error) {
	rows, err := s.secrets.ListPage(ctx, who, pageID)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(rows, func(row secrets.Secret) bool { return row.ID == secretID }), nil
}

// mayChangeSecretVisibility reports whether this principal may be offered the
// reveal or revoke control on a page.
//
// It asks the policy the question the route asks — Check(actor, PermDM,
// authz.Resource{}) — and nothing else. Two reasons, and the second is the
// important one. A grep test fails the build on a Role == comparison in a handler,
// so IsDM() is not available; and a control whose visibility is a hand-written
// copy of its gate is a control that can disagree with the gate, which is the same
// class of bug as a second redaction. Asking the policy is one line and is the
// same answer by construction.
//
// It is the page's view model that carries the answer, not the template: see
// SecretView.RevealAction, which is empty for a principal that may not use the
// control, and the AGENTS.md §7 rule that the absence of a capability must leave
// no broken control behind.
func (s *Server) mayChangeSecretVisibility(who authz.Principal) bool {
	return s.policy.Allows(who, authz.PermDM, authz.Resource{})
}
