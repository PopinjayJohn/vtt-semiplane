package httpapi_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// The page view's secret list, walked as every principal, over a vault whose
// fences the indexer refuses as well as ones it accepts.
//
// **The defect this file pins.** `Server.pageSecrets` used to build the page's
// list from `store.ListSecretRowsByPage` — the derived index — while
// `Server.renderBody` had already removed *every* secret span from the document
// it rendered. Those are different sets. A fence the indexer declined to write,
// which it does for an unresolvable `author=` and for anything failing
// `secrets.Secret.Valid`, therefore got no box, no lock, no body and no
// complaint: the body was stripped from the page and nothing took its place. The
// secret then existed only on the two surfaces that serve bytes, `/raw` and the
// editor, which is what "a secret appears only in edit mode" means in practice.
// `pageraw.go` states the rule the page view was breaking — the redaction is
// decided against the file, not the index — and `hiddenFences`/`lockFences` were
// already shared with the export and the conflict page. The page view was the one
// surface that never called them.
//
// **Why this drives HTTP rather than the service.** AGENTS.md §11: a handler test
// proves the handler works, not that anything points at it. The claim here is
// about the bytes a reader receives from `GET /p/{path}`, so that is what is
// requested, in both response shapes, and the same request is made to
// `GET /p/{path}/raw` for the same principal — the raw view is an independent
// implementation over the same rule, and the strongest single assertion in this
// file is that the two surfaces no longer disagree about the same fence.
//
// It is a separate vault from `campaignFiles` on purpose. That one is frozen, its
// ids and tokens are spelled out as literals in six other files, and every fence
// in it is indexed once the accounts exist — so it cannot exercise the branch
// this file is about. The expectations here are this file's own statement of who
// may read what, and they are checked against the raw view and (in
// TestTheExpectationTableAgreesWithThePolicy) against authz.CanReadSecret.

// pageSecretFiles is the vault: three pages, one of them owned by a player, and
// seven fences spanning every way a fence can fail to reach the index.
//
// The bodies are one token each, appearing nowhere else in the vault, so finding
// one in a response cannot be an accident of vocabulary.
var pageSecretFiles = map[string]string{
	"Index.md": "---\ntitle: Index\n---\n\n# Index\n\nNo secrets here.\n",
	"Indexed.md": "---\ntitle: Indexed\n---\n\n# Indexed\n\nBefore.\n\n" +
		// Indexed, `table`: the control. This is the case that already worked, and
		// it is here so a test that proves nothing cannot pass.
		fenceBody("11a1a1a1a1a1", "table", dmName, "Indexed and shared",
			"INDEXED-TABLE-TOKEN-0a1b2c") +
		// Indexed, `private`, and the page is owned by a player: so the owner may
		// read it, which is the ownership arm of the rule and the only fence on
		// this page a plain player is refused.
		fenceBody("22b2b2b2b2b2", "private", dmName, "Indexed and private",
			"INDEXED-PRIVATE-TOKEN-3d4e5f") +
		// Indexed, `dm`, with no body at all. An empty fence is a real state — it
		// is what a DM writes before they have written anything — and the page has
		// to say so rather than render an empty box.
		"```secret id=33c3c3c3c3c3 visibility=dm author=" + dmName +
		" created=2026-01-01T00:00:00Z title=\"Indexed and empty\"\n```\n\n" +
		"After.\n",
	"Unauthored.md": "---\ntitle: Unauthored\n---\n\n# Unauthored\n\nBefore.\n\n" +
		// Not indexed: `author=` names an account that does not exist, and
		// secrets.author_id is a foreign key. A DM may read it and a player may
		// not, so this is the ownership/author arms with neither of them.
		fenceBody("44d4d4d4d4d4", "dm", "nosuchaccount", "Unattributed and DM-only",
			"UNAUTH-DM-TOKEN-6e7f80") +
		// Not indexed, and `table`: every signed-in account is entitled to this one
		// whatever its author resolves to, because `table` is the one visibility
		// that is not about the author. This is the fence whose absence from the
		// page was a refusal of something the reader was entitled to.
		fenceBody("55e5e5e5e5e5", "table", "nosuchaccount", "Unattributed and shared",
			"UNAUTH-TABLE-TOKEN-9a0b1c") +
		"After.\n",
	"Broken.md": "---\ntitle: Broken\n---\n\n# Broken\n\nBefore.\n\n" +
		// Not indexed, and narrower than the file says: the directive carries a key
		// outside the closed set, so md and secrets.Parse both hold it secret with
		// the fail-safe private visibility. The file claims `table` and the app
		// serves it to a DM only. The page says so through the parser's own
		// problem, which is the point — the narrowing is visible, not silent.
		"```secret id=66f6f6f6f6f6 visibility=table author=" + dmName +
		" created=2026-01-01T00:00:00Z title=No Spaces Here\n" +
		"BROKEN-UNQUOTED-TOKEN-2d3e4f\n```\n\n" +
		// Not indexed, and no `id=` at all. The directive itself is readable, so
		// the visibility on it stands and a signed-in player is entitled; what the
		// fence has not got is an identity, which is why md's placeholder shows in
		// the lock and why nothing is offered that would post an id.
		"```secret visibility=table author=" + dmName +
		" created=2026-01-01T00:00:00Z title=\"No id at all\"\n" +
		"BROKEN-NOID-TOKEN-5f6a7b\n```\n\n" +
		"After.\n",

	// The two pages behind the size property. They are in the vault and not in
	// pageSecretFences, because the size test asks a question about two responses
	// rather than about one box, and folding it into the walk would have made
	// every cell carry a comparison it has nothing to do with.
	"Sized-one.md": sizePage("77a7a7a7a7a7", "x"),
	"Sized-two.md": sizePage("88b8b8b8b8b8",
		strings.Repeat("the quick brown fox jumps over the lazy dog. ", 400)),
}

// sizePage is one of the two pages behind the size property, built from one
// template so the pair differs **only** in the length of a body the reader is
// refused: same title, same heading, same directive, same id length, and — the
// one that is easy to forget — file names of equal length, because a page's own
// path appears in its rendered heading, in the shell's currentPageUrl signal and,
// because the page tree lists every page, in the other page's nav.
//
// The fence names an account the vault does not have, so the index holds no row
// for it. That is the point of putting the size property here rather than on an
// indexed fence: a fence with no index row is the only one this file's change
// reads a body for *without* the canonical predicate behind it, so it is where a
// size leak would be easiest to write — and where the assertion is worth having.
func sizePage(id, body string) string {
	return "---\ntitle: Sized\n---\n\n# Sized\n\n" +
		fenceBody(id, "dm", "nosuchaccount", "Sized", body)
}

// pageOwnerPage is the one page a player owns, and it is deliberately a page
// whose fences are all indexed: the ownership arm of authz.CanReadSecret is
// about *private* secrets, and a player who owns a page of unindexed fences
// would be testing the wrong thing with them.
const pageOwnerPage = "Indexed.md"

// pageSecretFence is one fence of the vault above and this file's statement of
// who may read it.
//
// The readers are named rather than computed, for the reason leaksuite_test.go
// keeps its own table: a test that asks authz whether a principal may read a
// secret has stopped being able to notice authz being wrong. The rule is
// restated once, here, and the cross-check in
// TestTheExpectationTableAgreesWithThePolicy evaluates it against
// authz.CanReadSecret over the real fixture state, so one description of the
// rule is checked against a second and against the raw view rather than against
// itself.
type pageSecretFence struct {
	// id is the fence's id on disk, or "" when it has none.
	id string
	// page is the vault-relative path the fence is written on.
	page string
	// token is the one string in the body that appears nowhere else.
	token string
	// author is the username the directive names, whether or not the vault has
	// such an account. A username this vault does not have resolves to author id
	// 0, and 0 is nobody — which is the whole reason the indexer refuses to write
	// the row rather than inventing an owner, and the reason a fence in this file
	// can be unindexed and still be readable by a DM.
	author string
	// visibility is the visibility the page's decision is made with. It is the
	// token on disk for every fence here but one: the unquoted-title fence
	// carries a key outside the closed set, so md and secrets.Parse both hold it
	// with the fail-safe private visibility, and that is the value the decision
	// used. The walk pins the consequence — a player is refused a fence the file
	// claims is shared — and this is the value behind it.
	visibility authz.Visibility
	// readers names the principals from leakRoles that may read the body.
	// Every principal not named is refused, which is what makes the anonymous
	// rows true without a case each.
	readers map[string]bool
	// indexed reports whether the index holds this fence, which is what decides
	// whether the page may offer a reveal for it.
	indexed bool
	// problem is the parser's own code for a fence something is wrong with, or ""
	// for a fence it read cleanly. It is the explanation the page owes that fence
	// from md, and a fence with one owes the page nothing further: the page's own
	// note is for a refusal only md would not have made.
	problem string
	// empty reports that the fence has no body, so the page has to say so rather
	// than render an empty box.
	empty bool
}

// revealed reports whether this fence's visibility makes it readable by every
// authenticated account, which is what decides the direction of the control the
// page offers for it and the tint its box wears.
func (f pageSecretFence) revealed() bool { return f.visibility == authz.VisibilityTable }

// attributed reports that the parser already named a problem for this fence, so
// the page owes no explanation of its own for the indexer's refusal.
func (f pageSecretFence) attributed() bool { return f.problem != "" }

// note is the line the page owes a reader of a fence the indexer refused and md
// did not, in the indexer's own wording — the same words sync writes to the log,
// because the two describe one refusal.
func (f pageSecretFence) note() string {
	what := "the fence names an author that is not a known account"
	if f.author == "" {
		what = "the fence names no author"
	}
	return secrets.ProblemAuthorUnknown + ": " + what + " (" + f.id + ")"
}

// pageSecretFences is every fence the walk asserts about.
var pageSecretFences = []pageSecretFence{
	{
		id: "11a1a1a1a1a1", page: "Indexed.md",
		token:      "INDEXED-TABLE-TOKEN-0a1b2c",
		author:     dmName,
		visibility: authz.VisibilityTable,
		readers:    map[string]bool{"admin": true, "dm": true, "page owner": true, "player": true, "other player": true},
		indexed:    true,
	},
	{
		id: "22b2b2b2b2b2", page: "Indexed.md",
		token:      "INDEXED-PRIVATE-TOKEN-3d4e5f",
		author:     dmName,
		visibility: authz.VisibilityPrivate,
		readers:    map[string]bool{"admin": true, "dm": true, "page owner": true},
		indexed:    true,
	},
	{
		id: "33c3c3c3c3c3", page: "Indexed.md",
		author:     dmName,
		visibility: authz.VisibilityDM,
		readers:    map[string]bool{"admin": true, "dm": true},
		indexed:    true,
		empty:      true,
	},
	{
		id: "44d4d4d4d4d4", page: "Unauthored.md",
		token:      "UNAUTH-DM-TOKEN-6e7f80",
		author:     "nosuchaccount",
		visibility: authz.VisibilityDM,
		readers:    map[string]bool{"admin": true, "dm": true},
	},
	{
		id: "55e5e5e5e5e5", page: "Unauthored.md",
		token:      "UNAUTH-TABLE-TOKEN-9a0b1c",
		author:     "nosuchaccount",
		visibility: authz.VisibilityTable,
		readers:    map[string]bool{"admin": true, "dm": true, "page owner": true, "player": true, "other player": true},
	},
	{
		// readers is empty, and that is the whole point of the row. The fence is
		// a `private` DM secret and a well-formed one would be readable by the
		// admin and the DM — so the entitlement is not in doubt and the row is
		// not asserting that a broken fence is secret from the table. It is
		// asserting the rule AGENTS.md §6 and TestAnUnunderstoodSecretFenceNeverBecomesPublic
		// exist for: a fence that cannot prove what closing it means is closed to
		// everybody, including the author. The indexer declines to write a row for
		// it, so a handler that treated "unindexed" as merely "not in the table"
		// would fall through to the readable branch and hand a DM the body — a
		// demotion wearing a lock's clothes, and the one failure this project
		// records as its worst.
		id: "66f6f6f6f6f6", page: "Broken.md",
		token:      "BROKEN-UNQUOTED-TOKEN-2d3e4f",
		author:     dmName,
		visibility: authz.VisibilityPrivate,
		readers:    map[string]bool{},
		problem:    md.ProblemSecretUnknownKey,
	},
	{
		// No id, so the lock's id is md's placeholder rather than a real one and
		// the exact label is asserted by shape rather than by value. The token is
		// still the fence's own, and the index's refusal is the parser's own
		// reported problem rather than a new one.
		// A `table` fence is readable by every signed-in principal, and this one
		// has no id. Readers is empty for the same reason as the row above and not
		// because the visibility says so: the strongest grant this app can hold
		// is still not enough to open a fence whose directive is unreadable.
		id: "", page: "Broken.md",
		token:      "BROKEN-NOID-TOKEN-5f6a7b",
		author:     dmName,
		visibility: authz.VisibilityTable,
		readers:    map[string]bool{},
		problem:    md.ProblemSecretMissingID,
	},
}

// newPageSecretFixture boots a fixture over pageSecretFiles as one principal.
//
// It reuses leakRole and its seven entries rather than declaring a second set of
// principals: the anonymous-with-read-on case is the one AGENTS.md §2.4 is about
// and it is only reachable through that row, and a second table would be a second
// chance for the two to disagree about who an anonymous reader is.
func newPageSecretFixture(t *testing.T, role leakRole) *fixture {
	t.Helper()
	fx := newFixtureWith(t, pageSecretFiles, func(c *config.Config) { c.AllowAnonymousRead = role.anonymousRead })
	fx.accounts()
	if role.minted {
		mintPlayer(t, fx, role.user, role.pass)
	}
	// After the reindex inside accounts(), never before: accounts() derives the
	// index, and a grant written before it names a page row that no longer exists,
	// so IsPageOwner answers false for the owner and the ownership arm of every
	// expectation in this file would be vacuous.
	if err := fx.addOwner(pageOwnerPage, fx.userID(playerName)); err != nil {
		t.Fatal(err)
	}
	return fx
}

// signIn is the principal's client, or an anonymous one.
func signIn(t *testing.T, fx *fixture, role leakRole) *session {
	t.Helper()
	s := fx.newSession()
	if role.user == "" {
		return s
	}
	resp := s.login(role.user, role.pass)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign %s in: status %d, want 303", role.user, resp.StatusCode)
	}
	drain(resp)
	return s
}

// TestThePageViewShowsEveryFenceTheFileHas is the walk: every fence, every
// principal, both response shapes, and the raw view beside it.
//
// **One box per fence, in file order, is the shape the page is asserted to have**
// and it is asserted before anything is read inside a box, because a page that
// rendered one box for two fences and none for a third would satisfy a
// whole-page "the body is absent" assertion while the secret it should have shown
// was on the page under the wrong caption. So the walk splits the page's secret
// section into one chunk per fence and asserts against a fence's own chunk.
//
// Per cell, then:
//
//   - the body is present exactly when this file says the principal may read it,
//     and the positive half is what keeps the negative half from passing against
//     a page that rendered nothing;
//   - a fence the principal may not read is a `secrets.LockPlaceholder` and
//     nothing else, and a fence it may read is not a lock;
//   - no `‹s:` sentinel appears anywhere on the page. A sentinel carries the
//     hidden body's length and a digest of it; it is a restore token for the
//     editor and never a display token;
//   - the raw view agrees, for the same principal and the same fence, so the two
//     surfaces cannot drift into disagreeing about who may read what.
func TestThePageViewShowsEveryFenceTheFileHas(t *testing.T) {
	t.Parallel()
	for _, role := range leakRoles {
		t.Run(role.name, func(t *testing.T) {
			t.Parallel()
			fx := newPageSecretFixture(t, role)
			s := signIn(t, fx, role)

			// The two anonymous rows are not a smaller version of this walk. With
			// anonymous read off there is no page to read, and the answer for it is
			// a redirect; the leak suite's positive control is where that is
			// established, and repeating a walk over a 303 would assert about the
			// login form's bytes.
			if role.user == "" && !role.anonymousRead {
				if got := s.status(s.get("/p/Indexed.md")); got != http.StatusSeeOther {
					t.Errorf("an anonymous reader with anonymous read off is answered %d, want 303: every assertion in this subtest would be about a login form", got)
				}
				return
			}

			for _, page := range distinctPages(pageSecretFences) {
				t.Run(page, func(t *testing.T) {
					t.Parallel()
					fences := pageFences(page)
					for _, asFragment := range []bool{false, true} {
						shape := "document"
						if asFragment {
							shape = "fragment"
						}
						t.Run(shape, func(t *testing.T) {
							body := getPageShape(t, s, page, asFragment)
							boxes := secretBoxes(t, body)
							if len(boxes) != len(fences) {
								t.Fatalf("the page renders %d secret boxes for %d fences in the file:\n%s",
									len(boxes), len(fences), pageExcerpt(body))
							}
							assertNoSentinel(t, body, role.name)
							raw := s.getOK("/p/" + page + "/raw")
							for i, f := range fences {
								want := f.readers[role.name]
								assertBox(t, boxes[i], f, role, shape)
								if got, askable := rawServes(raw, f); askable && got != want {
									t.Errorf("the raw view %s the body of %s, want it to %s; the page view and the raw view must not disagree about the same fence",
										present(got), f.label(), present(want))
								}
								assertExplained(t, body, f, role, shape)
							}
						})
					}
				})
			}
		})
	}
}

// rawServes reports whether the raw view's bytes carry a fence's token.
//
// A fence with no body has no token, so the question is unaskable rather than
// answered: reporting false for one would look exactly like a refusal, and
// reporting true would be a claim nothing on the page could support. The walk
// therefore does not ask it for a body-less fence, and says so here rather than
// returning a default.
func rawServes(raw string, f pageSecretFence) (found, askable bool) {
	if f.token == "" {
		return false, false
	}
	return strings.Contains(raw, f.token), true
}

// assertBox is every claim about one fence's own box.
func assertBox(t *testing.T, box string, f pageSecretFence, role leakRole, shape string) {
	t.Helper()
	locked := strings.Contains(box, `class="secret-locked"`)
	readable := strings.Contains(box, `class="secret-revealed"`) || strings.Contains(box, `class="secret-readable"`)

	if f.readers[role.name] {
		if locked {
			t.Errorf("%s: %s is a lock, want its body: the box and the decision disagree", shape, f.label())
		}
		if !readable {
			t.Errorf("%s: %s renders no body box at all, so the secret is on the page nowhere:\n%s", shape, f.label(), box)
		}
		if f.token != "" && !strings.Contains(box, f.token) {
			t.Errorf("%s: %s renders a body box without its own body:\n%s", shape, f.label(), box)
		}
		if f.empty && !strings.Contains(box, "This secret has no text yet") {
			t.Errorf("%s: %s has no body and renders an empty box rather than saying so:\n%s", shape, f.label(), box)
		}
		// The caption is the second half of the "renders correctly" claim, and it
		// is the half that was wrong: a DM's private note used to be captioned
		// "Shared with the table". The shared caption and the shared tint belong
		// to the shared fence alone.
		shared := strings.Contains(box, `class="secret-revealed"`)
		if shared && !strings.Contains(box, "Shared with the table") {
			t.Errorf("%s: %s is shared with the table and does not say so", shape, f.label())
		}
		if !shared && strings.Contains(box, "Shared with the table") {
			t.Errorf("%s: %s is not shared with the table and the page says it is:\n%s", shape, f.label(), box)
		}
		return
	}

	if !locked {
		t.Errorf("%s: %s renders neither a lock nor a body, so the fence's bytes were stripped from the page and nothing took their place:\n%s",
			shape, f.label(), pageExcerpt(box))
		return
	}
	if readable {
		t.Errorf("%s: %s is both locked and readable", shape, f.label())
	}
	if f.token != "" && strings.Contains(box, f.token) {
		t.Errorf("%s: the lock for %s carries its body", shape, f.label())
	}
	if f.id != "" {
		if want := secrets.LockPlaceholder(f.id); !strings.Contains(box, want) {
			t.Errorf("%s: the lock on %s does not carry %q:\n%s", shape, f.label(), want, box)
		}
		return
	}
	if !lockShapeRe.MatchString(box) {
		t.Errorf("%s: the lock on a fence with no id of its own is not the lock placeholder's shape:\n%s", shape, box)
	}
}

// assertExplained is the Problems list's claim: every fence the page cannot act
// on says so, and says it to the reader who can fix it.
//
// A fence md could not read is named by md's own code, which the page shows
// whoever can read the page. A fence md read cleanly and the indexer refused is
// named by the page's own note, and *only* to a principal who may read the
// fence — a directive is not shown to somebody the box has just refused, so the
// note is a fact about a secret this reader was refused and stops at the lock.
func assertExplained(t *testing.T, body string, f pageSecretFence, role leakRole, shape string) {
	t.Helper()
	switch {
	case f.attributed():
		if !strings.Contains(body, f.problem) {
			t.Errorf("%s: the page names no problem for %s, so a box has appeared with no reason beside it", shape, f.label())
		}
	case !f.indexed && f.readers[role.name]:
		if !strings.Contains(body, f.note()) {
			t.Errorf("%s: the page does not say that %s is not a secret the app can act on, although this principal can read it:\n%s", shape, f.label(), pageExcerpt(body))
		}
	default:
		// A healthy fence owes the page nothing, and a refused one owes the reader
		// nothing: a note here would be a fact about a secret the reader was not
		// shown, or a complaint about a fence that is working.
		if note := f.note(); !f.indexed && strings.Contains(body, note) {
			t.Errorf("%s: the page explains %s, which this principal may not read:\n%s", shape, f.label(), pageExcerpt(body))
		}
	}
}

// fencesOnPage is the page's fences in the order the file writes them, which is
// the order the page is asserted to render them in.
func pageFences(page string) []pageSecretFence {
	var out []pageSecretFence
	for _, f := range pageSecretFences {
		if f.page == page {
			out = append(out, f)
		}
	}
	return out
}

// secretBoxes splits a rendered page's secret section into one chunk per fence.
//
// The two markers are the two elements the template puts a fence in, and
// splitting on both rather than on the section's heading is what makes the
// count meaningful: a template that rendered two boxes for one fence, or none for
// another, changes the length of this list and the walk fails on the count
// before it reads anything.
func secretBoxes(t *testing.T, body string) []string {
	t.Helper()
	markers := []string{`<div class="secret-locked"`, `<details class="secret-`}
	at := []int{}
	for _, m := range markers {
		for i := 0; ; {
			j := strings.Index(body[i:], m)
			if j < 0 {
				break
			}
			at = append(at, i+j)
			i = i + j + len(m)
		}
	}
	if len(at) == 0 {
		return nil
	}
	sort.Ints(at)
	out := make([]string, 0, len(at))
	for i, start := range at {
		end := len(body)
		if i+1 < len(at) {
			end = at[i+1]
		}
		out = append(out, body[start:end])
	}
	return out
}

// label names a fence subtest.
func (f pageSecretFence) label() string {
	if f.id != "" {
		return f.id
	}
	return "no-id"
}

// lockShapeRe is the lock placeholder's shape, for the one fence that has no id
// of its own to put in it. Written out rather than derived from
// secrets.LockPlaceholder's implementation on purpose: this is the assertion
// that the fence's *own* id is what goes in the label, and an assertion built
// from the implementation cannot say that.
var lockShapeRe = regexp.MustCompile(`⟨secret:[0-9a-z-]+ hidden⟩`)

// sentinelShapeRe is md.Sentinel's shape. A page that rendered a buffer to be
// looked at must never contain one: it carries the hidden body's length and an
// eight-character digest of it, which is a measurement of something this reader
// was refused. AGENTS.md §6 is the rule; this is the check that it holds on the
// surface that changed.
var sentinelShapeRe = regexp.MustCompile(`‹s:[^›]*›`)

// assertNoSentinel is §6's "a sentinel is a restore token, not a display token"
// applied to the page view.
func assertNoSentinel(t *testing.T, body, who string) {
	t.Helper()
	if m := sentinelShapeRe.FindString(body); m != "" {
		t.Errorf("%s: the page renders %q, which is an editor restore token carrying a body length and a digest; a surface meant to be looked at uses %s",
			who, m, "secrets.LockPlaceholder")
	}
}

// TestThePageOffersARevealOnlyWhereTheRouteCouldAct is AGENTS.md §7 applied to
// the change: a fence with no index row has no id a reveal can name, so the
// button would answer 404 and its absence is what the page says instead.
//
// Which *direction* is offered is the fence's own, and asserting the exact verb
// rather than the presence of a form is the half that matters — a shared fence
// offers "hide it again" and no reveal, so a check that only looked for a form
// would pass on the wrong one and would not notice a page offering both.
func TestThePageOffersARevealOnlyWhereTheRouteCouldAct(t *testing.T) {
	t.Parallel()
	dm := signIn(t, newPageSecretFixture(t, leakRoles[1]), leakRoles[1])
	for _, f := range pageSecretFences {
		if f.id == "" {
			continue // nothing to name in a URL, which is the point of the row
		}
		t.Run(f.id, func(t *testing.T) {
			t.Parallel()
			body := dm.getOK("/p/" + f.page)
			offered := func(verb string) bool {
				return strings.Contains(body, `action="/p/`+f.page+`/secrets/`+f.id+`/`+verb+`"`)
			}
			wantReveal, wantRevoke := f.indexed && !f.revealed(), f.indexed && f.revealed()
			if got := offered("reveal"); got != wantReveal {
				t.Errorf("the page offers a reveal for %s: %t, want %t (indexed: %t, shared: %t)",
					f.label(), got, wantReveal, f.indexed, f.revealed())
			}
			if got := offered("revoke"); got != wantRevoke {
				t.Errorf("the page offers a revoke for %s: %t, want %t (indexed: %t, shared: %t)",
					f.label(), got, wantRevoke, f.indexed, f.revealed())
			}
		})
	}
}

// TestAnUnattributedFenceIsExplainedToThePersonWhoCanFixIt is docs/SECRETS.md's
// promise that such a fence "is reported on the page", which nothing reported
// before: the indexer's problem is a return value and a log line, and the page
// had no way to see it.
//
// Two halves, and the second is the one that matters. The note goes to a reader
// who may read *that* fence — a directive is not shown to somebody the box has
// just refused — and a principal refused the fence gets the lock and nothing
// else. Unauthored.md carries two refused fences, one of which this principal
// is entitled to, so the assertion names the fence rather than the page: "the
// page mentions secret.author_unknown somewhere" is true for this player too, and
// it would be the wrong thing to assert.
func TestAnUnattributedFenceIsExplainedToThePersonWhoCanFixIt(t *testing.T) {
	t.Parallel()
	dmFence := fenceWithID("44d4d4d4d4d4") // dm, no author: a DM may read it, a player may not

	dm := signIn(t, newPageSecretFixture(t, leakRoles[1]), leakRoles[1])
	dmBody := dm.getOK("/p/Unauthored.md")
	if !strings.Contains(dmBody, dmFence.note()) {
		t.Errorf("a DM is shown no explanation for the fence the index refused:\n%s", pageExcerpt(dmBody))
	}
	if !strings.Contains(dmBody, dmFence.id) {
		t.Error("the explanation does not name the fence, so it is a line about which secret")
	}

	// A player who owns no part of this page. They are entitled to the other fence
	// on it, so this page is the harder case rather than the easy one: the
	// principal is told about a fence they may read and not about one they may
	// not, on the same page, from the same list.
	player := signIn(t, newPageSecretFixture(t, leakRoles[3]), leakRoles[3])
	playerBody := player.getOK("/p/Unauthored.md")
	if strings.Contains(playerBody, dmFence.note()) {
		t.Errorf("a principal refused this fence is told about its directive, which is a fact about a secret it was not shown:\n%s", pageExcerpt(playerBody))
	}
	if !strings.Contains(playerBody, secrets.LockPlaceholder(dmFence.id)) {
		t.Error("the player is shown neither the fence nor the lock")
	}
	if !strings.Contains(playerBody, fenceWithID("55e5e5e5e5e5").note()) {
		t.Error("the player is not shown the explanation for the fence on this page they may read")
	}
}

// fenceWithID is the one row this file names in a sentence, so a reader does not
// have to go looking for which fence a test is about.
func fenceWithID(id string) pageSecretFence {
	for _, f := range pageSecretFences {
		if f.id == id {
			return f
		}
	}
	panic("no fence with id " + id + " in this file's table")
}

// TestTheExpectationTableAgreesWithThePolicy is the cross-check that makes this
// file's hand-written readers table a claim rather than a fixture.
//
// It is the argument leaksuite_test.go makes and the same reason: a table that
// drifted from the policy would have every walk in this file asserting the wrong
// thing and passing. It is evaluated over the real state the walk uses — the real
// page ids, the real ownership grant, the real author ids — so it is a statement
// about the fixture rather than about a table.
func TestTheExpectationTableAgreesWithThePolicy(t *testing.T) {
	t.Parallel()
	fx := newPageSecretFixture(t, leakRoles[0])
	// The one account this file's table names that no fixture helper creates, so
	// the "other player" row — the principal with no authorship and no ownership
	// anywhere — exists here too. Without it the cross-check would cover six of
	// the seven and say nothing.
	mintPlayer(t, fx, secondPlayerName, secondPlayerPass)
	// Every role's principal, built from the users row rather than from a literal
	// id, so a fixture that changed a role fails the cross-check instead of
	// quietly agreeing with itself.
	for _, role := range leakRoles {
		who := principalFor(t, fx, role)
		for _, page := range distinctPages(pageSecretFences) {
			pageID, ok := fx.pageIDByPath(page)
			if !ok {
				t.Fatalf("the index has no page for %s", page)
			}
			owner, err := store.IsPageOwner(context.Background(), fx.DB.Reader(), pageID, who.UserID)
			if err != nil {
				t.Fatalf("resolve ownership of %s: %v", page, err)
			}
			for _, f := range pageSecretFences {
				if f.page != page {
					continue
				}
				// The policy alone first: a hand-written model that agrees with
				// authz proves nothing unless it can also disagree with it, and
				// this one does — it is written out rather than derived.
				policy := authz.CanReadSecret(who, owner, fx.authorIDOrNobody(f.author), f.visibility)
				// Then the second half of the rule, which is not policy: a fence
				// whose directive is unreadable is closed to everyone whatever the
				// policy says about its visibility. Comparing against
				// CanReadSecret alone is what let the page view and the raw view
				// disagree about the same fence — both agreed with the policy and
				// applied a different answer on top of it.
				got := policy && !f.attributed()
				if got != f.readers[role.name] {
					t.Errorf("%s reading %s on %s: policy says %t and the fence is %s, so the answer is %t, this file's table says %t",
						role.name, f.label(), page, policy,
						map[bool]string{true: "unreadable", false: "well formed"}[f.attributed()],
						got, f.readers[role.name])
				}
			}
		}
	}
}

// authorIDOrNobody is the account id a fence's `author=` resolves to, and 0 for
// a username this vault does not have.
//
// 0 is nobody: no authenticated principal has it, so CanReadSecret's
// author-is-me arm cannot match on it, which is exactly the property that makes
// the indexer's refusal to invent an owner the safe direction. Answering it from
// the store rather than from this file's table is what makes the cross-check a
// statement about the fixture.
func (fx *fixture) authorIDOrNobody(username string) int64 {
	if username == "" {
		return 0
	}
	var id int64
	lookupErr := fx.DB.Reader().QueryRowContext(context.Background(), `SELECT id FROM users WHERE username = ?`, username).Scan(&id)
	if errors.Is(lookupErr, sql.ErrNoRows) {
		return 0
	}
	if lookupErr != nil {
		fx.t.Fatalf("resolve the account %q: %v", username, lookupErr)
	}
	return id
}

func distinctPages(fences []pageSecretFence) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fences {
		if !seen[f.page] {
			seen[f.page] = true
			out = append(out, f.page)
		}
	}
	return out
}

// TestTwoPagesDifferingOnlyInAHiddenBodyAreTheSameResponse is §8.8's rule, and
// the reason the new lock path has to hold it too: a response that varies with
// what is behind a lock is a disclosure with no text in it.
//
// It is the one assertion in this file that compares two responses rather than
// reading one, and it compares them for **byte equality** rather than for equal
// length. Equal length would pass against a page that leaked a fixed-width
// summary of a hidden body; byte equality, once the three things two pages are
// allowed to differ in have been normalised, cannot.
func TestTwoPagesDifferingOnlyInAHiddenBodyAreTheSameResponse(t *testing.T) {
	t.Parallel()
	// A player: the principal both pages refuse, which is the only principal for
	// which both responses are the same shape.
	role := leakRoles[3]
	s := signIn(t, newPageSecretFixture(t, role), role)
	const shortID, longID = "77a7a7a7a7a7", "88b8b8b8b8b8"
	short := sizedResponse(s.getOK("/p/Sized-one.md"), shortID)
	long := sizedResponse(s.getOK("/p/Sized-two.md"), longID)
	if short != long {
		t.Errorf("two pages differing only in the length of a body this principal may not read are not the same response: %d and %d bytes. The hidden body is 17 bytes in one and 17600 in the other, so every byte of the difference is a measurement of it",
			len(short), len(long))
	}
	if !strings.Contains(s.getOK("/p/Sized-two.md"), secrets.LockPlaceholder(longID)) {
		t.Error("the long page renders no lock, so the comparison above is between two pages that both rendered nothing")
	}
}

// sizedResponse removes the things two pages are legitimately allowed to differ
// in, and touches nothing else.
//
// They are the fence's own id, which the lock carries; each page's slug, which
// is in the rendered heading and in the shell's currentPageUrl signal; and the
// rowid of the *other* page, which the shell's related-pages panel names so the
// link-preview glue can find it. Both slugs are in the nav, because the page
// tree lists every page and so each response names the other one.
//
// The rowid is normalised for the same reason the slug is: it is a property of
// the file's insertion order and not of its contents, it is already all over the
// shell, and two pages that differ only in a hidden body are in different files
// and so have different rowids — which is a difference in where the file sits
// in the vault, not a measurement of what is behind the lock. What is left is
// compared byte for byte: every byte of the secret's box, and every byte of the
// body the page rendered in the body's place.
var wikilinkAttr = regexp.MustCompile(`data-wikilink="[0-9]+"`)

func sizedResponse(page, id string) string {
	for _, tok := range []string{id, "Sized-one.md", "Sized-two.md"} {
		page = strings.ReplaceAll(page, tok, "SIZE.md")
	}
	return wikilinkAttr.ReplaceAllString(page, `data-wikilink="ID"`)
}

// TestAPageWithNoSecretsSaysNothingAboutSecrets is the empty branch, and it is
// here because a section header over nothing is a heading promising a
// destination and offering none — the same fault AGENTS.md §7 calls a bug rather
// than a cosmetic one.
func TestAPageWithNoSecretsSaysNothingAboutSecrets(t *testing.T) {
	t.Parallel()
	fx := newPageSecretFixture(t, leakRoles[1])
	dm := signIn(t, fx, leakRoles[1])
	body := dm.getOK("/p/Index.md")
	for _, unwanted := range []string{"Secrets on this page", "secret-locked", "secret-revealed", "secret-readable"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("a page with no fence renders %q", unwanted)
		}
	}
}

// getPageShape asks for a page as a document or as a DataStar fragment.
//
// Both, because Server.Render branches on the request header and a walk that
// only asked for documents would leave the fragment half of the claim untested.
func getPageShape(t *testing.T, s *session, page string, asFragment bool) string {
	t.Helper()
	c := s.get("/p/" + page)
	if asFragment {
		c.headers = map[string]string{httpapi.DataStarRequestHeader: "true"}
	}
	resp := s.do(c)
	body := s.read(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /p/%s: status %d, want 200\n%s", page, resp.StatusCode, body)
	}
	return body
}

// present is a yes or a no for an assertion message, so a failure reads as a
// claim rather than as a boolean.
func present(yes bool) string {
	if yes {
		return "present"
	}
	return "absent"
}

// pageExcerpt is a bounded slice of a page, so a failure prints the box it is
// about rather than four hundred kilobytes of shell.
func pageExcerpt(body string) string {
	i := strings.Index(body, "Secrets on this page")
	if i < 0 {
		if len(body) > 1200 {
			return body[:1200] + "…"
		}
		return body
	}
	end := i + 1500
	if end > len(body) {
		end = len(body)
	}
	return body[i:end]
}
