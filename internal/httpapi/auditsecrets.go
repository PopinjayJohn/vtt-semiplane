package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// The secret audit trail, at GET /admin/secrets.
//
// It is the surface AGENTS.md §2.6a says had no gate and now has one:
// authz.PermAuditSecrets, its own row in the policy, and a service method that
// takes a principal and asks the policy before it looks anything up. The route
// mounts that method and passes the principal — not an id — which is the whole of
// what closing the gap required.
//
// **Nothing on this page is a body of anything.** A row carries the action, the
// account responsible, the secret's id, the visibility before and after, and when
// it happened. No title, no author of the secret, no length, no excerpt. That is
// not a matter of the template's restraint: the store's row has none of those
// fields, so the page cannot render them even if a template asked. §8.8's rule is
// kept here by not selecting the columns.

// adminSecretsPage answers GET /admin/secrets.
func (s *Server) adminSecretsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)

	// The principal goes in, not an id. AllEventsFor asks the policy first, so a
	// refused principal gets the refusal and never reaches a query — which is why
	// this handler has no "which account" parameter to validate and therefore no
	// second way to be pointed at somebody else's trail.
	events, err := s.secrets.AllEventsFor(ctx, who)
	if err != nil {
		if isDenial(err) {
			s.log.WarnContext(ctx, "a secret audit read was refused by the policy",
				"action", "http.secret_audit", "route", RouteFrom(ctx))
			s.writeError(w, r, http.StatusForbidden)
			return
		}
		s.fail(w, r, "read the secret audit trail", err)
		return
	}

	rows := make([]SecretEventRow, 0, len(events))
	actors, err := s.auditActors(ctx, events)
	if err != nil {
		s.fail(w, r, "read the accounts behind the audit trail", err)
		return
	}
	for _, ev := range events {
		rows = append(rows, SecretEventRow{
			Action:   ev.Action,
			Actor:    actors[ev.ActorID],
			SecretID: ev.SecretID,
			FromVis:  ev.FromVis,
			ToVis:    ev.ToVis,
			At:       ev.At,
		})
	}
	view := AdminSecretsView{
		Shell:      s.liveShell(r, "Secret audit"),
		Events:     rows,
		ShownLimit: secrets.AuditEventLimit,
	}
	// Authorization-dependent and never cached, for the reason every other
	// response this package produces that depends on the principal is.
	s.noStore(w)
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the secret audit trail", err)
	}
}

// auditActors resolves the accounts behind a set of events, by id, to the name a
// reader should be shown.
//
// The display name rather than the username, for the reason the party list gives:
// a page that printed login names would hand its reader the identifier of every
// account in the campaign, and an audit trail is read by people who do not already
// know them all. An id with no account is a fixed phrase rather than a blank
// cell — a blank cell is a column that failed to render, and an account that has
// been deleted is a fact the trail records rather than a rendering failure.
//
// Distinct ids are resolved once each rather than once per row, so the cost is the
// number of accounts that touched a secret and not the number of events.
func (s *Server) auditActors(ctx context.Context, events []store.SecretEvent) (map[int64]string, error) {
	out := make(map[int64]string, 2)
	for _, ev := range events {
		if _, seen := out[ev.ActorID]; seen {
			continue
		}
		u, err := store.GetUserByID(ctx, s.db.Reader(), ev.ActorID)
		switch {
		case errors.Is(err, store.ErrNoRows):
			out[ev.ActorID] = auditActorGone
		case err != nil:
			return nil, err
		default:
			name := u.DisplayName
			if name == "" {
				name = auditActorGone
			}
			out[ev.ActorID] = name
		}
	}
	return out, nil
}

// auditActorGone is what the actor column says when the account no longer exists.
//
// It is a sentence and not a blank so that a reader can tell "this account was
// deleted" from "this template forgot to render the cell", which look identical on
// a table and are not the same fact.
const auditActorGone = "an account that no longer exists"
