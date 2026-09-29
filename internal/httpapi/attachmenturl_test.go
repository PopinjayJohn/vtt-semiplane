package httpapi_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
)

// The vault attachmentURLVault carries, spelled once because the assertion this
// file exists to make is *the URL the page emits*, and an expectation typed at
// the call site would be a second copy of the string that can quietly disagree
// with the reference the index recorded — the same class of bug the serve route's
// own equality check exists to make impossible.
//
// Three shapes of reference on one page, because the renderer has three node
// kinds that can name a file and §8.8 serves all of them the same way:
//
//   - a markdown image under a subdirectory, the form the campaign fixture uses
//     and the half of the {name...} route the routing fix unblocked;
//   - a wikilink embed at the vault root, the form md.VaultResolver had;
//   - a reference inside a dm fence, which §8.8 serves to a DM and to nobody
//     else.
const (
	attachmentURLPage = "notes/Deep/Wardens.md"

	attachmentURLMap      = "assets/maps/harbour.png"
	attachmentURLPortrait = "orrin-at-the-bar.png"
	attachmentURLSecret   = "assets/portraits/orrin.png"
)

// attachmentURLBytes are the three files' contents. They are not images and
// nothing decodes them; what matters is that each is distinguishable, so a
// response can be attributed to the file the URL named.
var attachmentURLBytes = map[string]string{
	attachmentURLMap:      "\x89PNG\r\n\x1a\nthe-harbour",
	attachmentURLPortrait: "\x89PNG\r\n\x1a\norrin-at-the-bar",
	attachmentURLSecret:   "\x89PNG\r\n\x1a\norrin-real-face",
}

// attachmentURLFence is the dm fence on the page. Its id is this file's own and
// its body is an image reference and nothing else: the assertion is about the
// reference, and a body that carried prose would put an unrelated claim in the
// way of a failing one.
const attachmentURLFence = "f1f1f1f1f1f1"

func attachmentURLFiles() map[string]string {
	files := map[string]string{
		"Index.md": "---\ntitle: Index\ntype: note\n---\n\n# Index\n\nThe [[Wardens]] keep the harbour.\n",
		attachmentURLPage: "---\ntitle: The wardens\ntype: note\n---\n\n" +
			"# The wardens\n\n" +
			"The harbour, as the old map has it:\n\n" +
			"![" + attachmentURLMap + " map](" + attachmentURLMap + ")\n\n" +
			"And the landlord:\n\n![[" + attachmentURLPortrait + "]]\n\n" +
			fenceBody(attachmentURLFence, "dm", dmName, "Orrin's other name",
				"![Orrin's real face]("+attachmentURLSecret+")"),
	}
	for name, body := range attachmentURLBytes {
		files[name] = body
	}
	return files
}

// attachmentURLFor is the one URL the app serves a file on, built from a page
// path and the name the index recorded.
//
// It is spelled here rather than imported from md because the test's claim is
// that the rendered page reaches *this* address, not that two packages agree:
// a test that derived its expectation from the code under test would pass on a
// day the code emitted something else.
func attachmentURLFor(page, name string) string {
	return "/p/" + page + "/attachment/" + name
}

// attributeValues returns every value the rendered page carries for one HTML
// attribute, in document order.
//
// It matches the attribute by the space that precedes it inside a tag rather
// than by a whole-line or whole-tag match, so a page that emitted the URL in a
// tag with other attributes on it is still found. It returns the raw attribute
// text: the point of the test is what the page emitted, and decoding first
// would hide an encoding that is wrong.
func attributeValues(pageHTML, attribute string) []string {
	var out []string
	open := " " + attribute + `="`
	rest := pageHTML
	for {
		i := strings.Index(rest, open)
		if i < 0 {
			return out
		}
		rest = rest[i+len(open):]
		j := strings.IndexByte(rest, '"')
		if j < 0 {
			return out
		}
		out = append(out, rest[:j])
		rest = rest[j+1:]
	}
}

// hasAttribute reports whether the page carries any value for one HTML attribute
// whose text contains want. A player who is shown an image tag they may not
// fetch is an existence leak whatever the URL turns out to resolve to.
func hasAttribute(pageHTML, attribute, want string) bool {
	for _, v := range attributeValues(pageHTML, attribute) {
		if strings.Contains(v, want) {
			return true
		}
	}
	return false
}

// TestThePagePointsAtTheAttachmentItServes is the assertion §8.8 was missing.
//
// TestAttachmentInSecretIsNotServed asks the route directly, which is why a page
// whose every image pointed at a URL no route serves went unnoticed: the route
// answered correctly and nothing ever asked the page where its images were. So
// this test reads the src off the rendered page and follows *that*, and a
// regression in either half — the URL the renderer emits or the route that
// serves it — is a failure here rather than a broken image in a browser.
func TestThePagePointsAtTheAttachmentItServes(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, attachmentURLFiles())
	// accounts, not accountsFor: this vault has no Tavern, and a grant naming a
	// page that is not there is a failure in the fixture rather than in the code.
	fx.accounts()
	dm := fx.asUser(dmName, dmPass)
	player := fx.asUser(otherName, otherPass)

	page := dm.getOK("/p/" + attachmentURLPage)
	for _, name := range []string{attachmentURLMap, attachmentURLPortrait} {
		t.Run("the page points at "+name, func(t *testing.T) {
			t.Parallel()
			want := attachmentURLFor(attachmentURLPage, name)
			srcs := attributeValues(page, "src")
			if !slices.Contains(srcs, want) {
				t.Errorf("no img src is %q; the page carries %v", want, srcs)
			}
			if hasAttribute(page, "src", "harbour.png") && !hasAttribute(page, "src", want) {
				// A relative src is the exact bug: it is not in srcs above, so
				// this only fires when something else made the reader look.
				t.Errorf("the page carries a relative reference to %s rather than %q", name, want)
			}
			resp := dm.do(dm.get(want))
			got := dm.read(resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s: status %d, want 200\n%s", want, resp.StatusCode, got)
			}
			if got != attachmentURLBytes[name] {
				t.Errorf("GET %s served %d bytes, want the file's own %d", want, len(got), len(attachmentURLBytes[name]))
			}
		})
	}

	// A player may open the page and may fetch the public file, so the two
	// halves are worth one row: a page whose public image only a DM can load is
	// a broken control wearing a permission's clothes.
	t.Run("a player may follow the public reference", func(t *testing.T) {
		t.Parallel()
		playerPage := player.getOK("/p/" + attachmentURLPage)
		if !slices.Contains(attributeValues(playerPage, "src"), attachmentURLFor(attachmentURLPage, attachmentURLMap)) {
			t.Errorf("a player's page does not point at the public attachment")
		}
		want := attachmentURLFor(attachmentURLPage, attachmentURLMap)
		resp := player.do(player.get(want))
		got := player.read(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200\n%s", want, resp.StatusCode, got)
		}
		if got != attachmentURLBytes[attachmentURLMap] {
			t.Errorf("GET %s did not serve the file", want)
		}
	})

	// The other half of §8.8, and the half that is a leak rather than a broken
	// image. A player must be shown the lock, not a dead image tag: a URL the
	// player cannot use still confirms that a file exists at a name.
	//
	// The served half is the guarantee: the lock appears, and the URL answers
	// exactly as a file that does not exist does. The *name* is a separate
	// question with a known answer, recorded here rather than left unstated:
	//
	//   The indexer writes a pages row for every file in the vault, including a
	//   PNG, and a pages row has no visibility (AGENTS.md §7). So the campaign
	//   status panel lists assets/portraits/orrin.png as a "page" and a player
	//   sees the file's name, even though the only reference to it is inside a
	//   dm fence. The plan says the opposite — §5 "Images, PDFs, and audio live
	//   beside the pages... recorded in attachments... and referenced from pages
	//   through links rows of kind attachment, each of which carries the
	//   secret_id of the span it appears in" — so the indexer contradicts the
	//   plan here, and the plan is the better model.
	//
	// It is not asserted as correct here, and it is not fixed here either: the
	// fix is a change to what counts as a page, which is the indexer's model and
	// not §8.8's. So the name's appearance is asserted as the current behaviour,
	// and this test fails the moment that changes — in either direction. A reader
	// who finds it failing has the finding and the plan line, which is more use
	// than a silently-passing assertion or a skip.
	t.Run("a player is shown the lock, not a URL they may not fetch", func(t *testing.T) {
		t.Parallel()
		playerPage := player.getOK("/p/" + attachmentURLPage)
		if hasAttribute(playerPage, "src", attachmentURLSecret) {
			t.Errorf("a player's page carries an img src for the fence's attachment:\n%s", excerpt(playerPage))
		}
		if !strings.Contains(playerPage, secrets.LockPlaceholder(attachmentURLFence)) {
			t.Errorf("a player's page does not carry the lock placeholder for the fence")
		}
		// And the URL the reader *could* have guessed answers exactly as a file
		// that does not exist does, byte for byte.
		want := attachmentURLFor(attachmentURLPage, attachmentURLSecret)
		resp := player.do(player.get(want))
		got := player.read(resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: status %d, want 404\n%s", want, resp.StatusCode, got)
		}
		missing := player.do(player.get("/p/" + attachmentURLPage + "/attachment/no-such-file.png"))
		if absent := player.read(missing); absent != got {
			t.Errorf("a refused attachment and a file that does not exist answer differently:\n attachment: %q\n missing:   %q", got, absent)
		}
		// The recorded divergence. Remove this when the indexer stops writing a
		// pages row for a file, and replace it with the negative assertion it
		// exists to prompt.
		if !hasAttribute(playerPage, "href", attachmentURLSecret) {
			t.Errorf("the indexer no longer leaks a secret-only attachment's name into a player's page; " +
				"delete this assertion and assert its absence instead — see the comment above and plan §5")
		}
	})

	// A DM may fetch the file the fence names. The page cannot show it — see
	// TestASecretBodyIsNeverRenderedAsMarkdown, which is why the reference is
	// inside a <pre> — so the authorization claim is made where it is actually
	// decided: at the route.
	t.Run("a dm may fetch the reference inside a dm fence", func(t *testing.T) {
		t.Parallel()
		want := attachmentURLFor(attachmentURLPage, attachmentURLSecret)
		resp := dm.do(dm.get(want))
		got := dm.read(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200\n%s", want, resp.StatusCode, got)
		}
		if got != attachmentURLBytes[attachmentURLSecret] {
			t.Errorf("GET %s did not serve the file", want)
		}
		if hasAttribute(page, "src", "orrin.png") {
			t.Errorf("a dm's page carries an img for a body the renderer does not render")
		}
	})
}

func excerpt(s string) string {
	if len(s) > 400 {
		return s[:400] + "..."
	}
	return s
}
