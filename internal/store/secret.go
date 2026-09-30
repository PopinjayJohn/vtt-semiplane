package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// Secret is a row of the secrets table, plaintext body included.
//
// It is the one struct in this package that carries secret text, and it is
// returned by exactly two functions: GetSecretByID, which performs no
// authorization at all, and GetVisibleSecret, which does. A caller that uses the
// first one is responsible for authz.CanReadSecret before the body reaches
// anything. There is no third path.
type Secret struct {
	// ID is 12 lowercase hex characters, stable across edits and reveals.
	ID string
	// PageID is the page the fence lives on.
	PageID int64
	// Ordinal is the fence's position in the file, from 0.
	Ordinal int
	// Visibility is one of the three authz.Visibility values.
	Visibility authz.Visibility
	// AuthorID is the account the fence directive names as author.
	AuthorID int64
	// Title is the optional label from the fence directive.
	Title string
	// Body is the plaintext between the fence lines.
	Body string
	// BodyHash is the sha256 of Body, for change detection and the tripwire. It
	// is not a substitute for authorization.
	BodyHash []byte
	// CreatedAt is from the fence directive when present, else when indexed.
	CreatedAt time.Time
	// UpdatedAt is when the row was last written.
	UpdatedAt time.Time
}

// The two projections below are qualified with the `s` alias even where the
// statement has no join. GetVisibleSecret and friends join `pages p`, and an
// unqualified `id` is ambiguous the moment that happens — which is how a
// working query and a broken one end up in the same file.
const secretColumns = `s.id, s.page_id, s.ordinal, s.visibility, s.author_id,
	COALESCE(s.title, ''), s.body, s.body_hash, s.created_at, s.updated_at`

func scanSecret(s RowScanner) (Secret, error) {
	var (
		sec        Secret
		ordinal    int64
		visibility string
		createdAt  string
		updatedAt  string
	)
	if err := s.Scan(&sec.ID, &sec.PageID, &ordinal, &visibility, &sec.AuthorID,
		&sec.Title, &sec.Body, &sec.BodyHash, &createdAt, &updatedAt); err != nil {
		return Secret{}, err
	}
	sec.Ordinal = int(ordinal)
	sec.Visibility = authz.Visibility(visibility)
	var err error
	if sec.CreatedAt, err = ParseTime(createdAt); err != nil {
		return Secret{}, err
	}
	if sec.UpdatedAt, err = ParseTime(updatedAt); err != nil {
		return Secret{}, err
	}
	return sec, nil
}

func scanSecretRow(s RowScanner) (SecretRow, error) {
	var (
		row        SecretRow
		ordinal    int64
		visibility string
		title      sql.NullString
		createdAt  string
		updatedAt  string
	)
	if err := s.Scan(&row.ID, &row.PageID, &ordinal, &visibility, &row.AuthorID,
		&title, &row.BodyHash, &createdAt, &updatedAt); err != nil {
		return SecretRow{}, err
	}
	row.Ordinal = int(ordinal)
	row.Visibility = visibility
	row.Title = title.String
	var err error
	if row.CreatedAt, err = ParseTime(createdAt); err != nil {
		return SecretRow{}, err
	}
	if row.UpdatedAt, err = ParseTime(updatedAt); err != nil {
		return SecretRow{}, err
	}
	return row, nil
}

const secretRowColumns = `s.id, s.page_id, s.ordinal, s.visibility, s.author_id,
	COALESCE(s.title, ''), s.body_hash, s.created_at, s.updated_at`

// InsertSecret writes a secret row.
func InsertSecret(ctx context.Context, e Execer, s Secret) error {
	if _, err := e.ExecContext(ctx,
		`INSERT INTO secrets
		 (id, page_id, ordinal, visibility, author_id, title, body, body_hash, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.PageID, s.Ordinal, string(s.Visibility), s.AuthorID,
		nullIfEmpty(s.Title), s.Body, s.BodyHash,
		FormatTime(s.CreatedAt), FormatTime(s.UpdatedAt)); err != nil {
		return fmt.Errorf("store: insert secret on page %d: %w", s.PageID, err)
	}
	return nil
}

// GetSecretByID returns a secret including its plaintext body, with NO
// authorization check.
//
// It exists for the paths that must handle a secret they are not yet allowed to
// show: reveal and revoke rewrite only the visibility token in the file, the
// indexer replaces the row wholesale, and the audit view records an event about
// it. Every one of those callers passes the body to authz.CanReadSecret, or to
// the filesystem, before anything renders it. A caller that returns this to a
// request has skipped a check that no compiler can enforce.
func GetSecretByID(ctx context.Context, q Queryer, id string) (Secret, error) {
	s, err := scanSecret(q.QueryRowContext(ctx, `SELECT `+secretColumns+` FROM secrets s WHERE s.id = ?`, id))
	if err != nil {
		return Secret{}, wrapNoRows(err, "secret "+id)
	}
	return s, nil
}

// publicOnlySQL returns the extra filter an unauthenticated principal needs on a
// query that mixes public rows with secret-derived ones, and the empty string
// for an authenticated one.
//
// It exists because authz.SecretVisibleSQL cannot express §8.2's bottom row on
// its own. The canonical predicate admits a table-visible secret on visibility
// alone, with no authentication term, so an anonymous principal evaluating it
// sees every revealed secret — while authz.CanReadSecret requires an
// authenticated principal for that same visibility and does not. One rule, two
// answers, and the anonymous one is the permissive one.
//
// The fix narrows to the predicate's own public branch (a null or empty
// secret_id) rather than filtering on a visibility value, so it applies no SQL
// visibility comparison of its own and can only ever remove rows. For a query
// that is entirely secret-derived there is nothing to keep, and
// maySeeAnySecret short-circuits it instead.
//
// The right fix is in the shared predicate, where every other phase will meet
// this too; it is reported as a finding rather than patched here, because authz
// is not this package's to change and the predicate is pinned by a test.
func publicOnlySQL(p authz.Principal, publicTest string) string {
	if p.Authenticated() {
		return ""
	}
	return " AND " + publicTest
}

// maySeeAnySecret reports whether a principal may be shown any secret at all.
// §8.2 says an unauthenticated request sees none, under any visibility; see
// publicOnlySQL for why the predicate does not already guarantee it.
func maySeeAnySecret(p authz.Principal) bool { return p.Authenticated() }

// GetVisibleSecret returns a secret only if p may read it, evaluating the
// canonical predicate. An invisible secret is reported as ErrNoRows, not as a
// forbidden error: the existence of the id is itself the thing being hidden.
func GetVisibleSecret(ctx context.Context, q Queryer, p authz.Principal, id string) (Secret, error) {
	if !maySeeAnySecret(p) {
		return Secret{}, wrapNoRows(ErrNoRows, "secret "+id)
	}
	uid, isDM := p.Bind()
	s, err := scanSecret(q.QueryRowContext(ctx,
		`SELECT `+secretColumns+`
		 FROM secrets s
		 JOIN pages p ON p.id = s.page_id
		 WHERE s.id = ? AND `+authz.SecretVisibleSQL,
		id, sql.Named("uid", uid), sql.Named("is_dm", isDM)))
	if err != nil {
		return Secret{}, wrapNoRows(err, "secret "+id)
	}
	return s, nil
}

// UpdateSecret replaces a secret row. The id is the key and does not change: a
// secret's identity is stable across edits and reveals, which is what lets a
// revision be re-segmented against the same ids.
func UpdateSecret(ctx context.Context, e Execer, s Secret) error {
	if _, err := e.ExecContext(ctx,
		`UPDATE secrets
		 SET page_id = ?, ordinal = ?, visibility = ?, author_id = ?, title = ?,
		     body = ?, body_hash = ?, created_at = ?, updated_at = ?
		 WHERE id = ?`,
		s.PageID, s.Ordinal, string(s.Visibility), s.AuthorID, nullIfEmpty(s.Title),
		s.Body, s.BodyHash, FormatTime(s.CreatedAt), FormatTime(s.UpdatedAt), s.ID); err != nil {
		return fmt.Errorf("store: update secret %s: %w", s.ID, err)
	}
	return nil
}

// DeleteSecretByPage removes every secret on a page. The indexer calls it before
// reinserting the file's fences, and DeleteSecretTextsOfPage first, because the
// cascade does not reach the search index.
func DeleteSecretByPage(ctx context.Context, e Execer, pageID int64) error {
	if err := DeleteSecretTextsOfPage(ctx, e, pageID); err != nil {
		return err
	}
	if _, err := e.ExecContext(ctx, `DELETE FROM secrets WHERE page_id = ?`, pageID); err != nil {
		return fmt.Errorf("store: delete secrets of page %d: %w", pageID, err)
	}
	return nil
}

// ListSecretRowsByPage returns a page's secrets without their bodies, for the
// editor's marker list and the reveal UI. A body never enters a list result.
func ListSecretRowsByPage(ctx context.Context, q Queryer, pageID int64) ([]SecretRow, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+secretRowColumns+` FROM secrets s WHERE s.page_id = ? ORDER BY s.ordinal`, pageID)
	if err != nil {
		return nil, fmt.Errorf("store: list secrets of page %d: %w", pageID, err)
	}
	var out []SecretRow
	err = ForEach(rows, func(r Rows) error {
		row, scanSecretRowErr := scanSecretRow(r)
		if scanSecretRowErr != nil {
			return fmt.Errorf("store: scan secret: %w", scanSecretRowErr)
		}
		out = append(out, row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListVisibleSecretRowsByPage returns only the secrets p may read. The bodies
// are never selected, so this cannot leak one even by accident.
func ListVisibleSecretRowsByPage(ctx context.Context, q Queryer, p authz.Principal, pageID int64) ([]SecretRow, error) {
	if !maySeeAnySecret(p) {
		return nil, nil
	}
	uid, isDM := p.Bind()
	rows, err := q.QueryContext(ctx,
		`SELECT `+secretRowColumns+`
		 FROM secrets s
		 JOIN pages p ON p.id = s.page_id
		 WHERE s.page_id = ? AND `+authz.SecretVisibleSQL+`
		 ORDER BY s.ordinal`,
		pageID, sql.Named("uid", uid), sql.Named("is_dm", isDM))
	if err != nil {
		return nil, fmt.Errorf("store: list visible secrets of page %d: %w", pageID, err)
	}
	var out []SecretRow
	err = ForEach(rows, func(r Rows) error {
		row, scanSecretRowErr := scanSecretRow(r)
		if scanSecretRowErr != nil {
			return fmt.Errorf("store: scan secret: %w", scanSecretRowErr)
		}
		out = append(out, row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CountVisibleSecrets is the number of a page's secrets p may read, for the
// context panel. It uses the identical predicate as the list.
func CountVisibleSecrets(ctx context.Context, q Queryer, p authz.Principal, pageID int64) (int, error) {
	if !maySeeAnySecret(p) {
		return 0, nil
	}
	uid, isDM := p.Bind()
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM secrets s
		 JOIN pages p ON p.id = s.page_id
		 WHERE s.page_id = ? AND `+authz.SecretVisibleSQL,
		pageID, sql.Named("uid", uid), sql.Named("is_dm", isDM)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count visible secrets of page %d: %w", pageID, err)
	}
	return n, nil
}

// SecretEvent is one row of the append-only audit table. It records that
// something happened to a secret, never what the secret said.
type SecretEvent struct {
	// ID is the surrogate key.
	ID int64
	// SecretID is the secret the event is about.
	SecretID string
	// ActorID is the account that performed the action.
	ActorID int64
	// Action is create, reveal, revoke, edit, delete or view_denied.
	Action string
	// FromVis is the visibility before the action, or empty.
	FromVis string
	// ToVis is the visibility after the action, or empty.
	ToVis string
	// At is when it happened.
	At time.Time
}

// The action values the CHECK constraint allows.
const (
	// SecretActionCreate records a fence entering the vault.
	SecretActionCreate = "create"
	// SecretActionReveal records a secret being pushed to the table.
	SecretActionReveal = "reveal"
	// SecretActionRevoke records a revealed secret being hidden again.
	SecretActionRevoke = "revoke"
	// SecretActionEdit records a body or visibility change from the app.
	SecretActionEdit = "edit"
	// SecretActionDelete records a fence being removed.
	SecretActionDelete = "delete"
	// SecretActionViewDenied records a read that authorization refused.
	SecretActionViewDenied = "view_denied"
)

// AppendSecretEvent writes one audit row.
func AppendSecretEvent(ctx context.Context, e Execer, ev SecretEvent) (int64, error) {
	var id int64
	err := e.QueryRowContext(ctx,
		`INSERT INTO secret_events (secret_id, actor_id, action, from_vis, to_vis, at)
		 VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
		ev.SecretID, ev.ActorID, ev.Action, nullIfEmpty(ev.FromVis),
		nullIfEmpty(ev.ToVis), FormatTime(ev.At)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: append secret event for %s: %w", ev.SecretID, err)
	}
	return id, nil
}

// ListSecretEventsBySecret returns a secret's audit trail, newest first.
func ListSecretEventsBySecret(ctx context.Context, q Queryer, secretID string) ([]SecretEvent, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT id, secret_id, actor_id, action, COALESCE(from_vis, ''), COALESCE(to_vis, ''), at
		 FROM secret_events WHERE secret_id = ? ORDER BY at DESC, id DESC`, secretID)
	if err != nil {
		return nil, fmt.Errorf("store: list events for secret %s: %w", secretID, err)
	}
	return collectSecretEvents(rows)
}

// ListSecretEventsByActor returns one account's audit trail, newest first.
func ListSecretEventsByActor(ctx context.Context, q Queryer, actorID int64) ([]SecretEvent, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT id, secret_id, actor_id, action, COALESCE(from_vis, ''), COALESCE(to_vis, ''), at
		 FROM secret_events WHERE actor_id = ? ORDER BY at DESC, id DESC`, actorID)
	if err != nil {
		return nil, fmt.Errorf("store: list events by actor %d: %w", actorID, err)
	}
	return collectSecretEvents(rows)
}

func collectSecretEvents(rows *sql.Rows) ([]SecretEvent, error) {
	var out []SecretEvent
	err := ForEach(rows, func(r Rows) error {
		var (
			ev SecretEvent
			at string
		)
		if err := r.Scan(&ev.ID, &ev.SecretID, &ev.ActorID, &ev.Action, &ev.FromVis, &ev.ToVis, &at); err != nil {
			return fmt.Errorf("store: scan secret event: %w", err)
		}
		var err error
		if ev.At, err = ParseTime(at); err != nil {
			return err
		}
		out = append(out, ev)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
