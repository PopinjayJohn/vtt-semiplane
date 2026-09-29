package sample

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// The campaign is content, and content is the one thing in this repository that
// no test in the tree can reach into by accident. Nothing compiles it, nothing
// imports it, and a sentence that quietly stopped being true would be caught by
// nobody — the app would go on demonstrating a page type that no longer exists
// and a wikilink graph that no longer connects, and the demonstration would
// still look like a demonstration.
//
// TestSampleCampaignExercisesEveryFeature is the campaign's only enforcement, so
// it is worth being clear about what it can and cannot catch. It reads the
// embedded bytes through the same parser the app uses, so a fence this test
// calls well formed is one internal/md calls well formed, and a link it calls
// resolved is one internal/sync would resolve. What it cannot catch is a page
// that reads well and says nothing useful; that is a reviewer's job, and the
// reason this gate is about structure is that structure is what rots on its own.

const (
	// pageTypeHouseRule is houserules.PageTypeHouseRule, spelled rather than
	// imported. The value is a convention a feature plugin reads, and a gate
	// that imported the constant could not notice the convention being dropped:
	// it would follow the rename and keep agreeing. The leak suite's own
	// campaignPageTypes table pins its ids for the same reason.
	pageTypeHouseRule = "houserule"
	// pageTypeSession is documented by the campaign's frontmatter page as a
	// known value and read by no code as a type — the session panel reads the
	// session *tag* (store.TagSession) and a page whose type is unrecognised
	// renders as an ordinary note. It is named here so that a second
	// undocumented type is a test failure rather than a slow drift, and so the
	// distinction is written down where the next person reads the campaign.
	pageTypeSession = "session"
	// reservedTypesCarried are the reserved page-type ids the campaign
	// demonstrates. character and rule are the two internal/systems/dnd5e
	// claims with CapCharacterSheet and CapRules, so those are the two with a
	// viewer behind them; map and encounter are reserved and currently
	// unclaimed, and the campaign carries them so the vocabulary is exercised
	// rather than described. token is reserved, unclaimed, and absent — a
	// reserved name with no viewer behind it is a name held for a future
	// plugin, and a page demonstrating one would demonstrate nothing.
	reservedTypesCarried = "character rule map encounter"
)

// campaignPage is one file of the campaign, parsed.
type campaignPage struct {
	// rel is the campaign-relative path.
	rel string
	// src is the file's bytes.
	src []byte
	// doc is what the app's own parser makes of them.
	doc *md.Doc
	// ex is what the app's own extractor makes of them.
	ex md.Extracted
}

// pages parses the whole campaign the way the indexer would. Every assertion
// below runs over this, so none of them re-implements a parser.
func pages(t *testing.T) []campaignPage {
	t.Helper()
	files, err := Files()
	if err != nil {
		t.Fatalf("the embedded campaign cannot be read: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("the embedded campaign holds no files")
	}
	r := md.New(md.Options{})
	out := make([]campaignPage, 0, len(files))
	for _, f := range files {
		doc := md.Parse(f.Name, f.Content)
		ex, _ := md.Extract(doc, r)
		out = append(out, campaignPage{rel: f.Name, src: f.Content, doc: doc, ex: ex})
	}
	return out
}

// fenceLine finds the info string of a ```secret fence opening at or after an
// offset. The directive is re-read with the app's own parser rather than
// pattern-matched, so a fence this test calls a dm secret is one internal/md
// calls a dm secret.
func fences(src []byte) []md.Directive {
	// The whole info string, so the word `secret` is part of what is handed to
	// the parser: md.ParseFenceDirective reads a fence's info string, not the
	// part of it after the word, and handing it the remainder is a directive it
	// refuses as "not a secret fence".
	open := regexp.MustCompile("(?m)^```(secret[^`\n]*)$")
	var out []md.Directive
	for _, m := range open.FindAllSubmatch(src, -1) {
		dir, err := md.ParseFenceDirective(string(m[1]))
		if err != nil {
			// A directive that cannot be parsed at all still opens a secret
			// fence, and the campaign carries exactly one of those on purpose;
			// the malformed-fence subtest looks for it directly.
			continue
		}
		out = append(out, dir)
	}
	return out
}

// TestTheEmbeddedCampaignMatchesTheSourceTree keeps the two halves of this
// package honest.
//
// campaign.go embeds the campaign one top-level entry at a time, and
// unembeddable.go carries one page that no embed pattern can name, so neither
// half is a plain mirror of campaign/ any more. That is a real door for a file
// to stop shipping without anything failing, and this is what closes it: every
// embedded file is compared with the source tree byte for byte, in both
// directions, so a new top-level folder, a deleted page and a hand-copied
// duplicate are all test failures.
//
// It is skipped when the source tree is not there — a distribution's test
// binary has no campaign/ beside it — which is the right way round: the tree is
// the source of truth and the embedded copy is derived, so the check belongs
// where the source is.
func TestTheEmbeddedCampaignMatchesTheSourceTree(t *testing.T) {
	t.Parallel()
	root := filepath.Join("campaign")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("no source campaign beside the test binary (%v): the embedded copy cannot be compared with anything", err)
	}

	onDisk := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		onDisk[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk the source campaign: %v", err)
	}

	files, err := Files()
	if err != nil {
		t.Fatalf("the embedded campaign cannot be read: %v", err)
	}
	embedded := make(map[string]string, len(files))
	for _, f := range files {
		if prev, dup := embedded[f.Name]; dup {
			t.Errorf("the embedded campaign carries %s twice, and the two copies differ: %v",
				f.Name, prev != string(f.Content))
		}
		embedded[f.Name] = string(f.Content)
	}

	var missing, extra []string
	for name := range onDisk {
		if _, ok := embedded[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range embedded {
		if _, ok := onDisk[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	for _, name := range missing {
		// A page that is in the repository and not in the binary is a page the
		// operator never receives, and the most likely way that happens is a new
		// top-level folder that nobody added to the //go:embed list.
		t.Errorf("%s is in campaign/ and is not embedded: add it to the //go:embed list in campaign.go", name)
	}
	for _, name := range extra {
		t.Errorf("%s is embedded and is not in campaign/: the binary would carry a page the repository does not have", name)
	}
	for name, want := range onDisk {
		if got, ok := embedded[name]; ok && got != want {
			t.Errorf("%s differs between campaign/ and the embedded copy: the hand-carried copy in unembeddable.go has drifted", name)
		}
	}
}

// TestSampleCampaignExercisesEveryFeature is the gate on the content.
//
// The leak suite in internal/httpapi walks every route as seven principals over
// its own hand-built fixture, and that fixture is not this campaign — it exists
// because a leak walk needs its page ids and its tokens pinned as literals. Two
// demonstrations therefore exist, and nothing but this test keeps them from
// becoming two different things: this one says the campaign a DM reads actually
// exercises what the app claims to do, and the leak suite says the app does not
// leak while doing it.
func TestSampleCampaignExercisesEveryFeature(t *testing.T) {
	t.Parallel()
	all := pages(t)
	byName := map[string]campaignPage{}
	for _, p := range all {
		byName[p.rel] = p
	}

	t.Run("page types the host knows", func(t *testing.T) {
		t.Parallel()
		known := map[string]bool{md.DefaultPageType: true, pageTypeHouseRule: true}
		for _, id := range plugin.ReservedPageTypes() {
			known[id.ID] = true
		}
		// One value the campaign documents and the app handles as a note. See
		// the constant's comment.
		known[pageTypeSession] = true

		counts := map[string]int{}
		for _, p := range all {
			if p.ex.PageType == "" {
				t.Errorf("%s has no page type; md should have fallen back to %q", p.rel, md.DefaultPageType)
			}
			counts[p.ex.PageType]++
			if !known[p.ex.PageType] {
				t.Errorf("%s declares type: %s, which the host knows nothing about: it renders as a %s and demonstrates nothing",
					p.rel, p.ex.PageType, md.DefaultPageType)
			}
		}
		want := []string{md.DefaultPageType, pageTypeHouseRule, pageTypeSession}
		for _, id := range strings.Fields(reservedTypesCarried) {
			want = append(want, id)
		}
		for _, id := range want {
			if counts[id] == 0 {
				t.Errorf("the campaign carries no page of type %s, so the %s it is there to demonstrate is not demonstrated",
					id, id)
			}
		}
		// The houserules feature groups its index by the system a rule belongs
		// to, and a rule with no system falls into a single bucket — so a
		// campaign page of that type without the key demonstrates the fallback
		// rather than the feature.
		for _, p := range all {
			if p.ex.PageType != pageTypeHouseRule {
				continue
			}
			if md.FieldString(p.doc.Fields, "system") == "" {
				t.Errorf("%s is a %s page with no system: key, so the rules index cannot group it",
					p.rel, pageTypeHouseRule)
			}
		}
	})

	t.Run("the wikilink graph connects", func(t *testing.T) {
		t.Parallel()
		keys := make([]md.PageKey, 0, len(all))
		for _, p := range all {
			if !strings.HasSuffix(p.rel, ".md") {
				continue
			}
			keys = append(keys, md.PageKey{ID: md.PageID(len(keys) + 1), Path: p.rel, Aliases: p.ex.Aliases})
		}
		res := md.NewResolver(keys)
		if res.Len() == 0 {
			t.Fatal("no pages to resolve links against")
		}

		// README.md is the campaign's documentation of the syntax and it
		// necessarily contains links that resolve to nothing, because that is
		// what the syntax looks like. Every other page is prose, and a link in
		// prose that reaches nothing is a broken link a DM will click.
		const readme = "README.md"
		for _, p := range all {
			for _, l := range p.ex.Links {
				// An in-page anchor has nothing to resolve: `[[#heading]]` is
				// flagged as a self-link, and the markdown spelling
				// `[text](#anchor)` says the same thing without the flag, so
				// the fragment is the test rather than either spelling.
				if l.Kind == md.LinkAttachment || l.SelfLink || l.Target == "" ||
					strings.HasPrefix(l.Target, "#") {
					continue
				}
				if _, ok := res.Resolve(l.Target); ok {
					continue
				}
				if p.rel == readme {
					continue
				}
				t.Errorf("%s:%d links to [[%s]], which names no page in the campaign", p.rel, l.Line, l.TargetRaw)
			}
		}
		// And the documentation is only honest if there is still something in it
		// that resolves to nothing: a README whose examples all happen to match
		// a page has stopped being an example of a broken link.
		dangling := 0
		if r, ok := byName[readme]; ok {
			for _, l := range r.ex.Links {
				if l.Kind == md.LinkAttachment || l.SelfLink || l.Target == "" ||
					strings.HasPrefix(l.Target, "#") {
					continue
				}
				if _, ok := res.Resolve(l.Target); !ok {
					dangling++
				}
			}
		}
		if dangling == 0 {
			t.Errorf("%s has no unresolvable link left, so the syntax it documents is no longer demonstrated", readme)
		}
	})

	t.Run("the tags the app reads", func(t *testing.T) {
		t.Parallel()
		// The campaign panel lists the newest session log by its tag, not by
		// its type, so this is the tag that has to be on a page for the panel
		// to have anything to show.
		var tagged bool
		for _, p := range all {
			for _, tag := range p.ex.Tags {
				if tag.Name == store.TagSession {
					tagged = true
				}
			}
		}
		if !tagged {
			t.Errorf("no page carries the %s tag, so the campaign panel's session list is empty in the campaign it demonstrates",
				store.TagSession)
		}
		// A tag on exactly one page proves a tag list and nothing else: the
		// panel is a cloud, and a cloud of singletons is not a demonstration.
		owners := map[string]int{}
		for _, p := range all {
			for _, tag := range p.ex.Tags {
				owners[tag.Name]++
			}
		}
		shared := 0
		for _, n := range owners {
			if n > 1 {
				shared++
			}
		}
		if shared == 0 {
			t.Error("every tag in the campaign is on exactly one page, so the tag list demonstrates nothing beyond the page")
		}
	})

	t.Run("secret fences in each visibility", func(t *testing.T) {
		t.Parallel()
		vis := map[authz.Visibility]int{}
		rules := map[authz.Visibility]int{}
		for _, p := range all {
			dirs := fences(p.src)
			if got, want := len(p.doc.SecretSpans()), len(dirs); got != want && got != 1 {
				// The malformed fence is the one that parses to no directive and
				// still produces a span; it is pinned separately below. Anything
				// else is a fence the extractor and the scanner disagree about.
				t.Errorf("%s: md found %d secret spans and %d directives were readable", p.rel, got, want)
			}
			for _, d := range dirs {
				vis[d.Visibility]++
				if p.ex.PageType == pageTypeHouseRule {
					rules[d.Visibility]++
				}
			}
		}
		// §2.8.1's split: the ten house rules are six table-visible, three
		// private and one DM-only. That is the shape the survey asked for and
		// the reason the house rules are in the campaign at all.
		want := map[authz.Visibility]int{
			authz.VisibilityTable: 6, authz.VisibilityPrivate: 3, authz.VisibilityDM: 1,
		}
		for v, n := range want {
			if rules[v] != n {
				t.Errorf("the house rules carry %d %s secrets, want %d: the split the survey asked for is 6 table, 3 private, 1 dm",
					rules[v], v, n)
			}
		}
		// And the campaign as a whole, not only the rules, shows each of the
		// three, so the shared/DM split on an ordinary page is demonstrated too.
		for _, v := range []authz.Visibility{authz.VisibilityTable, authz.VisibilityPrivate, authz.VisibilityDM} {
			if vis[v] == 0 {
				t.Errorf("no %s secret anywhere in the campaign, so the %s reader is demonstrated by nothing", v, v)
			}
		}
		// Every well-formed fence names an author, and an account that does not
		// exist yet is the documented state of a fresh vault: the indexer
		// refuses the row, the fence stays hidden, and RetryUnresolvedAuthors
		// picks it up once setup creates the account. A fence with no author
		// would never be picked up by anything.
		for _, p := range all {
			for _, d := range fences(p.src) {
				if d.Author == "" {
					t.Errorf("%s has a secret fence that names no author, and no account will ever be created for the empty name", p.rel)
				}
				if len(d.ID) != 12 {
					t.Errorf("%s has a secret fence whose id is %q, which is not the 12 hexadecimal characters the on-disk syntax requires", p.rel, d.ID)
				}
				if d.Created == "" {
					t.Errorf("%s has a secret fence with no created= timestamp", p.rel)
				}
			}
		}
	})

	t.Run("the story-page secrets", func(t *testing.T) {
		t.Parallel()
		// The campaign's own Overview states its inventory: fifteen secret
		// blocks, ten inside the house rules and five on story pages, of which
		// one is dm, two are private, one is table and one is deliberately
		// malformed. Asserting the campaign's claim about itself is a stronger
		// gate than asserting a count chosen here, because a page added or
		// removed has to change a sentence a DM reads rather than a number a
		// test happened to pick.
		type secret struct {
			page      string
			vis       authz.Visibility
			author    string
			malformed bool
		}
		var story []secret
		for _, p := range all {
			if p.ex.PageType == pageTypeHouseRule {
				continue
			}
			for _, d := range fences(p.src) {
				// The malformed fence is malformed in the way the repository's own
				// history records: its title is unquoted, so the value runs on and
				// the rest of the line parses as unknown keys. The directive
				// still parses — HasUnknown is what says the app cannot rely on
				// it — and the fence is still a secret, which is the property
				// the subtest below checks and the reason it is here.
				story = append(story, secret{
					page: p.rel, vis: d.Visibility, author: d.Author, malformed: d.HasUnknown,
				})
			}
		}
		want := map[authz.Visibility]int{
			authz.VisibilityTable: 1, authz.VisibilityPrivate: 2, authz.VisibilityDM: 1,
		}
		malformed, privateAuthors := 0, map[string]bool{}
		for _, s := range story {
			if s.malformed {
				malformed++
				continue
			}
			if s.vis == authz.VisibilityPrivate {
				privateAuthors[s.author] = true
			}
		}
		got := map[authz.Visibility]int{}
		for _, s := range story {
			if !s.malformed {
				got[s.vis]++
			}
		}
		if len(got) != len(want) || malformed != 1 {
			t.Fatalf("the campaign carries %d story-page secrets, want five: one table, two private, one dm and one deliberately malformed (found %v, %d malformed)",
				len(story), got, malformed)
		}
		for v, n := range want {
			if got[v] != n {
				t.Errorf("the campaign carries %d story-page %s secrets, want %d", got[v], v, n)
			}
		}
		// "Two private — one written by the game master and one written by a
		// player" is the whole demonstration of a second author's secrets being
		// somebody else's, so two authors and not one.
		if len(privateAuthors) != 2 {
			t.Errorf("the two private story-page secrets are authored by %d accounts (%v), want two: one is the game master's and one is a player's",
				len(privateAuthors), keys(privateAuthors))
		}
	})

	t.Run("a fence that cannot be read is hidden, not demoted", func(t *testing.T) {
		t.Parallel()
		// The failure this repository once shipped: a directive this package
		// could not understand was made public, so a fence whose title contained
		// an unquoted space served its body in plaintext to a player. The
		// campaign carries a fence that trips exactly that, on purpose, and the
		// only thing worth asserting about it is that it is not public.
		const broken = "Notes/A fence that will not open.md"
		p, ok := byName[broken]
		if !ok {
			t.Fatalf("the campaign has no %s, so the fail-closed rule has no example to demonstrate it", broken)
		}
		var found bool
		for _, pr := range p.doc.Problems {
			if pr.Code == md.ProblemSecretUnknownKey || pr.Code == md.ProblemSecretBadDirective {
				found = true
			}
		}
		if !found {
			t.Errorf("%s records no problem, so the fence in it is one the app understood — and then it demonstrates nothing", broken)
		}
		spans := p.doc.SecretSpans()
		if len(spans) != 1 {
			t.Fatalf("%s has %d secret spans, want 1", broken, len(spans))
		}
		if public := p.doc.PublicBody(); bytes.Contains(public, []byte("THE QUARTER BELLS AT MIDNIGHT")) {
			t.Errorf("%s put the body of an unreadable secret fence in its public body: a fence that claims secrecy gets it, whatever its directive says",
				broken)
		}
	})

	t.Run("the secret-only attachment", func(t *testing.T) {
		t.Parallel()
		// One image a reader may see and one only a principal who may read the
		// fence may see. The second is the whole point of §6's attachment rule
		// and it has to be here for the rule to be demonstrated at all.
		public, secret := map[string]bool{}, map[string]bool{}
		for _, p := range all {
			for _, a := range p.ex.Attachments {
				if a.Span.Secret() {
					secret[a.Name] = true
				} else {
					public[a.Name] = true
				}
			}
		}
		if len(public) == 0 {
			t.Error("no attachment is referenced from public text, so an ordinary image link is demonstrated by nothing")
		}
		if len(secret) == 0 {
			t.Error("no attachment is referenced only from inside a secret, so the rule that one is served only to readers who may see the fence is demonstrated by nothing")
		}
		for name := range public {
			if secret[name] {
				t.Errorf("%s is referenced both from public text and from inside a secret, so it is not the secret-only case", name)
			}
		}
		// The references are written as full vault-relative paths on the
		// assumption that the campaign is extracted under Root. If Root moves,
		// these break silently, and they are the coupling that makes Root a
		// constant in this package rather than a literal in the walk.
		for _, p := range all {
			for _, a := range p.ex.Attachments {
				if !strings.HasPrefix(a.Name, Root+"/") {
					t.Errorf("%s:%d references %s, which is not under %s: an attachment reference is resolved against the vault root, not the page's directory",
						p.rel, a.Line, a.Name, Root)
				}
			}
		}
	})
}

// TestFilesIsSortedAndWhole covers the enumeration the walk iterates, because
// every property above is a property of a list and a list that quietly loses or
// duplicates an entry takes them all with it.
func TestFilesIsSortedAndWhole(t *testing.T) {
	t.Parallel()
	files, err := Files()
	if err != nil {
		t.Fatalf("read the campaign: %v", err)
	}
	seen := map[string]bool{}
	for i, f := range files {
		if f.Name == "" {
			t.Fatalf("entry %d has no name", i)
		}
		if strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, "\\") {
			t.Errorf("%q is not a campaign-relative slash path", f.Name)
		}
		if seen[f.Name] {
			t.Errorf("%s appears twice in the enumeration", f.Name)
		}
		seen[f.Name] = true
		if len(f.Content) == 0 {
			t.Errorf("%s is empty: an extracted empty file is a page the indexer will not index", f.Name)
		}
		if i > 0 && files[i-1].Name >= f.Name {
			t.Errorf("the enumeration is not sorted: %q comes after %q", f.Name, files[i-1].Name)
		}
	}
	// FS and Files must agree exactly. They diverged once, deliberately: one page
	// carried an apostrophe in its file name, //go:embed's fileNameOK refuses
	// that character, and the page was carried as a hand-maintained Go constant
	// beside the real file. A second copy of a page that a DM edits is a second
	// copy that rots, and the drift test only proved they had not rotted *yet*.
	// So the two are one set, and a name //go:embed cannot carry is now a build
	// failure rather than a maintenance obligation.
	embedded := 0
	if err := fs.WalkDir(FS(), ".", func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			embedded++
		}
		return nil
	}); err != nil {
		t.Fatalf("walk the embedded filesystem: %v", err)
	}
	if embedded != len(files) {
		t.Errorf("FS holds %d files and Files enumerates %d; they are the same set, so a page is either "+
			"not embedded or not enumerated", embedded, len(files))
	}
}

// keys is a map's keys, for a failure message that has to name them.
func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
