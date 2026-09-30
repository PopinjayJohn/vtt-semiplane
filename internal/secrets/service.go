package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// ErrNotInFile reports a secret the index knows and the file does not.
//
// It means the file moved under the index: the fence was deleted, or the whole
// page was rewritten without it, between the last index pass and this call. The
// reveal is refused rather than guessed at, because writing a visibility token
// for a fence that is not there would mean inserting one into a line that has
// some other meaning.
var ErrNotInFile = errors.New("the secret is no longer in the page file")

// ErrNotAVisibility reports a requested visibility that is not one of the three
// the format defines. It is a sentinel so a handler can answer 400 rather than
// 500, and so a test does not have to match on the message.
var ErrNotAVisibility = errors.New("visibility is not private, dm or table")

// Reindexer re-derives one page's index rows after a file mutation.
//
// It is the seam to internal/sync. sync sits above this package in the
// dependency order, so it cannot be imported here and the dependency is declared
// as an interface that the indexer satisfies structurally. One method, because
// both jobs — republish the page, and tell the live-push subscribers it
// changed — are the same event: the file was rewritten and the index is
// re-derived from it.
type Reindexer interface {
	// Reindex reads the page at a vault-relative path and brings its index rows
	// and invalidations up to date.
	Reindex(ctx context.Context, path string) error
}

// RaceLostError reports a lost race on a page's file without carrying either
// version of it.
//
// vault.ConflictError holds the bytes that are on disk and the bytes the writer
// meant to put there, and on a page with a secret fence those bytes *are* a
// secret body. A reveal that returned one would have handed its caller a way to
// read the whole file through errors.As, which is why this type exists: it
// matches errors.Is(err, vault.ErrConflict) so the caller still knows to render
// a conflict, and it is not a vault.ConflictError, so nothing downstream can
// reach the bytes.
type RaceLostError struct {
	// Path is the vault-relative page path.
	Path string
	// SecretID is the secret whose reveal or revoke lost the race.
	SecretID string
	// Reason says what was being done, for a log line.
	Reason string
}

// Error implements error. It names the path and the secret and nothing else.
func (e *RaceLostError) Error() string {
	return fmt.Sprintf("vault: %s lost a race on %s: the file changed on disk", e.Reason, e.Path)
}

// Unwrap makes errors.Is(err, vault.ErrConflict) true.
func (e *RaceLostError) Unwrap() error { return vault.ErrConflict }

// Options configures a Service.
type Options struct {
	// DB is the index. Required.
	DB *store.DB
	// Writer is the only way a vault file is changed. Required.
	Writer *vault.Writer
	// Policy decides who may reveal and revoke. Required.
	Policy authz.Policy
	// Reindexer republishes the page after the file changes. Required: a reveal
	// that wrote the file and did not re-derive the index would leave the
	// secret visible in the file and invisible in the app.
	Reindexer Reindexer
	// Log receives the audit trail's own records. Nil discards.
	Log *obs.Logger
	// Clock is the time source for the event timestamps. Nil is the system
	// clock.
	Clock obs.Clock
}

// Service is the secret write path: reveal, revoke, and the one authorised way
// to read a body back.
//
// It owns everything above md, which owns parsing and the visibility rewrite.
// A reveal is a file mutation of one token and nothing else: the fence survives,
// so the secret keeps its id, its audit trail and its revocability, and the
// bytes outside the token are untouched. Removing the fence instead would leave
// plaintext that can never again be hidden, never audited and never revoked.
type Service struct {
	db        *store.DB
	writer    *vault.Writer
	policy    authz.Policy
	reindexer Reindexer
	log       *obs.Logger
	clock     obs.Clock
}

// NewService returns a Service.
func NewService(opts Options) (*Service, error) {
	switch {
	case opts.DB == nil:
		return nil, errors.New("secrets: an index database is required")
	case opts.Writer == nil:
		return nil, errors.New("secrets: a vault writer is required")
	case opts.Reindexer == nil:
		return nil, errors.New("secrets: a reindexer is required")
	}
	clock := opts.Clock
	if clock == nil {
		clock = obs.SystemClock
	}
	log := opts.Log
	if log == nil {
		log = obs.Discard()
	}
	return &Service{
		db:        opts.DB,
		writer:    opts.Writer,
		policy:    opts.Policy,
		reindexer: opts.Reindexer,
		log:       log,
		clock:     clock,
	}, nil
}

// Reveal makes a secret readable by every authenticated user.
//
// It rewrites the visibility token in the fence to `table`, writes the file
// through vault.Writer, records the event, bumps the authorization generation
// and re-derives the index. The generation bump is what terminates a live-push
// stream that was rendering the secret as hidden: the stream carries a trigger,
// never content, and its bytes come from the ordinary handler under the
// subscriber's own principal, so the only thing that has to happen is for the
// stream to notice that the answer it would now give is different.
func (s *Service) Reveal(ctx context.Context, actor authz.Principal, secretID string) error {
	return s.SetVisibility(ctx, actor, secretID, VisibilityTable)
}

// Revoke hides a revealed secret again.
//
// It is Reveal in the other direction plus the purge: the secret's copy in the
// search index is deleted rather than filtered, so the terms in a revoked secret
// stop being findable immediately instead of at the next restart, and the
// authorization generation moves so every stream is torn down.
func (s *Service) Revoke(ctx context.Context, actor authz.Principal, secretID string) error {
	return s.SetVisibility(ctx, actor, secretID, VisibilityPrivate)
}

// SetVisibility moves a secret to a visibility, revealing it or revoking it.
//
// Only a DM or an admin may do this. A page owner may create and edit their own
// secrets — that is PermWriteSecret, and it is a different permission — but
// ownership grants authoring rights, not broadcast rights. `table` is a
// broadcast: it is the one visibility that reaches every other player, so it is
// gated on the campaign role and not on anything the author can grant.
func (s *Service) SetVisibility(ctx context.Context, actor authz.Principal, secretID string, to authz.Visibility) error {
	// The role check comes first, before any lookup. A principal that may not
	// reveal gets the same answer for every id, and cannot use the time it takes
	// to say so as an oracle for which ids exist.
	if err := s.policy.Check(actor, authz.PermDM, authz.Resource{}); err != nil {
		return err
	}
	if !to.Valid() {
		return fmt.Errorf("%w: %q", ErrNotAVisibility, to)
	}

	// GetSecretByID performs no authorization, which is correct here: the
	// policy has already established that the actor is a DM, and a DM may read
	// every secret. The body it returns goes to md and to the filesystem and to
	// nothing else.
	sec, err := store.GetSecretByID(ctx, s.db.Reader(), secretID)
	if err != nil {
		return err
	}
	page, err := store.GetPageByID(ctx, s.db.Reader(), sec.PageID)
	if err != nil {
		return err
	}
	// The path came out of the index, but Resolve is still the constructor used:
	// it re-establishes containment on the resolved path, and a corrupted index
	// row should not be able to name a file outside the vault.
	p, err := vault.Resolve(s.writer.Root, page.Path)
	if err != nil {
		return err
	}
	onDisk, err := vault.Read(ctx, p)
	if err != nil {
		return err
	}

	doc := md.Parse(page.Path, onDisk)
	rewritten, problems := md.SetVisibility(doc, to, secretID)
	for _, pr := range problems {
		if pr.Code == md.ProblemSecretUnknownID {
			return fmt.Errorf("%w: secret %s on %s", ErrNotInFile, secretID, page.Path)
		}
	}
	if bytes.Equal(rewritten, onDisk) {
		// The file already says this. Writing it again would produce a
		// self-write, a watch event and a second audit row for a change nobody
		// made, and the audit trail is only useful while it is true.
		s.log.InfoContext(ctx, "secret is already at that visibility",
			"action", "secret.visibility", "path", page.Path,
			"secret_id", secretID, "to_vis", string(to))
		return nil
	}

	action, reason := store.SecretActionReveal, "reveal"
	if to != VisibilityTable {
		action, reason = store.SecretActionRevoke, "revoke"
	}
	err = s.writer.Save(ctx, vault.SaveRequest{
		Path:            page.Path,
		NewContent:      rewritten,
		BaseContentHash: vault.Hash(onDisk),
		ActorID:         actor.UserID,
		ExpectPerm:      authz.PermWriteSecret,
	})
	if errors.Is(err, vault.ErrConflict) {
		// Someone wrote the file between our read and ours. The bytes are in
		// vault's error and stay there: see RaceLostError.
		return &RaceLostError{Path: page.Path, SecretID: secretID, Reason: reason}
	}
	if err != nil {
		return err
	}

	// The event and the generation move in one transaction, so a crash cannot
	// leave a generation bumped with no event explaining it, or an event with no
	// generation to terminate the streams it invalidated. The file write is
	// already outside any transaction, because the file is canonical and the
	// index is derived: a crash here leaves the file right and the index stale,
	// and the reconciliation scan rebuilds the index from the file.
	tx, err := s.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("secrets: begin the %s of %s: %w", reason, secretID, err)
	}
	defer func() { _ = tx.Rollback() }()
	if action == store.SecretActionRevoke {
		// The FTS content is gone rather than hidden. A revoked secret whose
		// body is still in secret_text would keep answering MATCH for the terms
		// it contained, which is a search-visible existence leak the
		// authorization predicate never sees.
		if deleteSecretTextErr := store.DeleteSecretText(ctx, tx, secretID); deleteSecretTextErr != nil {
			return deleteSecretTextErr
		}
	}
	if _, appendSecretEventErr := store.AppendSecretEvent(ctx, tx, store.SecretEvent{
		SecretID: secretID,
		ActorID:  actor.UserID,
		Action:   action,
		FromVis:  string(sec.Visibility),
		ToVis:    string(to),
		At:       s.clock(),
	}); appendSecretEventErr != nil {
		return appendSecretEventErr
	}
	generation, err := store.BumpAuthzGeneration(ctx, tx)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("secrets: commit the %s of %s: %w", reason, secretID, err)
	}

	// Reindexed after the durable writes, so the index is derived from a file
	// that already says the new thing. A failure here is reported rather than
	// swallowed: the file and the audit trail are right, the index is stale, and
	// the caller should know that the change is not yet visible.
	if err := s.reindexer.Reindex(ctx, page.Path); err != nil {
		return fmt.Errorf("secrets: %s wrote %s but the index could not be updated: %w",
			reason, page.Path, err)
	}
	s.log.Audit(ctx, "secret visibility changed",
		"action", reason, "page_path", page.Path, "actor", actor.Username,
		"secret_id", secretID,
		"from_vis", string(sec.Visibility), "to_vis", string(to),
		"authz_generation", generation)
	s.log.InfoContext(ctx, "secret visibility changed",
		"action", reason, "path", page.Path, "actor_id", actor.UserID,
		"secret_id", secretID,
		"from_vis", string(sec.Visibility), "to_vis", string(to),
		"authz_generation", generation)
	return nil
}

// Load returns one secret, body included, if actor may read it.
//
// It is the only read path in this package and the only one P6's handlers may
// use. The decision is made by the canonical SQL predicate rather than by a Go
// re-statement of it, because a second implementation of "who may read this" is
// the bug authz.SecretVisibleSQL exists to prevent. An invisible secret is
// reported as store.ErrNoRows rather than as a denial: the existence of the id
// is itself the thing being hidden.
func (s *Service) Load(ctx context.Context, actor authz.Principal, secretID string) (Secret, error) {
	row, err := store.GetVisibleSecret(ctx, s.db.Reader(), actor, secretID)
	if err != nil {
		return Secret{}, err
	}
	out := Secret{
		ID:         row.ID,
		PageID:     row.PageID,
		Ordinal:    row.Ordinal,
		Visibility: row.Visibility,
		AuthorID:   row.AuthorID,
		Body:       row.Body,
		BodyHash:   row.BodyHash,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}
	return out, nil
}

// ListPage returns the secrets of a page that actor may read, without their
// bodies. A body never enters a list result, so a panel that lists a page's
// secrets cannot leak one by a mistake in the renderer.
func (s *Service) ListPage(ctx context.Context, actor authz.Principal, pageID int64) ([]Secret, error) {
	rows, err := store.ListVisibleSecretRowsByPage(ctx, s.db.Reader(), actor, pageID)
	if err != nil {
		return nil, err
	}
	out := make([]Secret, 0, len(rows))
	for _, r := range rows {
		out = append(out, Secret{
			ID:         r.ID,
			PageID:     r.PageID,
			Ordinal:    r.Ordinal,
			Visibility: Visibility(r.Visibility),
			AuthorID:   r.AuthorID,
			Title:      r.Title,
			BodyHash:   r.BodyHash,
			CreatedAt:  r.CreatedAt,
			UpdatedAt:  r.UpdatedAt,
		})
	}
	return out, nil
}

// CountPage is the number of rows ListPage would return, from the identical
// predicate. A panel that shows a number its own list does not agree with is an
// existence leak, and the only defence is that there is nothing to disagree.
func (s *Service) CountPage(ctx context.Context, actor authz.Principal, pageID int64) (int, error) {
	return store.CountVisibleSecrets(ctx, s.db.Reader(), actor, pageID)
}

// AuditEventLimit is how many rows AllEventsFor returns.
//
// It is the same bound httpapi.ShownLimit puts on the broken-links panel, for the
// same reason: a list surface that grows with the campaign is a response a single
// GET can make arbitrarily large, and an audit page is a diagnostic rather than a
// dataset. It is a *read* bound and not a retention policy — secret_events has
// none, deliberately, because the plan's retention numbers (§8.10's 50 and 5) are
// for revisions and a revoke has to stay visible in the trail after the fact. The
// newest rows are the ones an audit is read for, and the query orders them that
// way, so the cap drops the oldest.
const AuditEventLimit = 200

// AllEventsFor returns one account's secret audit trail to a principal the policy
// admits, newest first.
//
// It exists because store.ListSecretEventsByActor took an account id and no
// principal at all, so anything that wanted to show a trail had to hand it an id
// and inherit no gate — which is the live gap AGENTS.md §2.6a records, closed for
// one more surface with one more wrapper.
//
// **The policy is asked before the query, and the order is the security property
// rather than a style choice.** A principal that may not read the trail gets the
// same answer, in the same time, for every request, and cannot use the difference
// between a refusal and a fast empty list as an inventory of what has happened to
// the campaign's secrets. A lookup first would answer "no events" for an account
// that has none and "forbidden" for one that has some, which is the oracle.
//
// The scope is one account across every secret rather than the whole table, and
// that is the only thing the store can be asked for: ListSecretEventsByActor is
// anchored on actor_id, and the package's other query, ListSecretEventsBySecret,
// needs an id the *caller* would have to supply — which is exactly the enumeration
// §2.6a forbids. A campaign-wide trail needs one more store query, a new query
// belongs in store by the dependency order, and until that query exists this is the
// smaller of the two disclosures: a DM sees what they did, and nobody sees what
// another account did.
func (s *Service) AllEventsFor(ctx context.Context, actor authz.Principal) ([]store.SecretEvent, error) {
	if err := s.policy.Check(actor, authz.PermAuditSecrets, authz.Resource{}); err != nil {
		return nil, err
	}
	events, err := store.ListSecretEventsByActor(ctx, s.db.Reader(), actor.UserID)
	if err != nil {
		return nil, err
	}
	// The cap is applied here and not in the query because the query has no LIMIT.
	// A single GET that renders an account's entire history is the same lever
	// ShownLimit closes on the broken-links panel, and the fix is the same one.
	if len(events) > AuditEventLimit {
		events = events[:AuditEventLimit]
	}
	return events, nil
}

// EventsFor returns a secret's audit trail for a principal who may see it, newest
// first.
//
// It exists because Events did not take a principal and had no permission behind
// it, which AGENTS.md §6a records as a live gap: a route mounted for it would
// have inherited no gate, because the authorisation is this package's job and a
// route that does not ask cannot be granted one. The gate is PermAuditSecrets,
// which exists for exactly this and is not PermDM: the trail is a separable
// capability, and naming the permission after what it grants is what keeps the
// next route from reusing the wrong one.
//
// The check comes before the lookup, for SetVisibility's reason: a principal who
// may not see the trail gets the same answer for every id, and cannot use the
// time it takes to say so as an oracle for which ids exist. There is no resource
// check after it because a DM reads every secret — that is the definition of the
// role — so asking again would refuse nobody and cost a lookup per call.
func (s *Service) EventsFor(ctx context.Context, actor authz.Principal, secretID string) ([]store.SecretEvent, error) {
	if err := s.policy.Check(actor, authz.PermAuditSecrets, authz.Resource{}); err != nil {
		return nil, err
	}
	return store.ListSecretEventsBySecret(ctx, s.db.Reader(), secretID)
}
