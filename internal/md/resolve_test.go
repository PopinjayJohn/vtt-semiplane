package md

import "testing"

// TestLinkResolution walks §5.6's order and the three tie-breaks that make it
// deterministic. The resolver is the only place a wikilink becomes a page id,
// so an ambiguity here is a link that points at the wrong page, which is worse
// than a link that points at nothing: a broken link is visible, a wrong one is
// not.
func TestLinkResolution(t *testing.T) {
	t.Parallel()
	// A vault with every ambiguity the order has to break.
	pages := []PageKey{
		{ID: 1, Path: "Gundren.md"},
		{ID: 2, Path: "Party/Tavern.md"},
		{ID: 3, Path: "Nights/Long/deep/Page.md"},
		{ID: 4, Path: "Notes/Page.md"},
		{ID: 5, Path: "Page.md"},
		// Two pages called Tavern: the shorter path wins, and on a tie the
		// lexicographically smaller one.
		{ID: 6, Path: "Tavern.md"},
		{ID: 7, Path: "World/Tavern.md"},
		{ID: 8, Path: "World/inn/Tavern.md"},
		// An alias that collides with a real basename. The basename wins,
		// because the path is consulted first.
		{ID: 9, Path: "deep/Secret.md", Aliases: []string{"Page", "The Vault"}},
		// A page reached only by its alias.
		{ID: 10, Path: "World/Ice.md", Aliases: []string{"The Vault Door", "Second Alias"}},
		// An alias with a path separator in it, to check the alias index is
		// not silently split.
		{ID: 11, Path: "deep/East.md", Aliases: []string{"a/b"}},
	}
	r := NewResolver(pages)

	cases := []struct {
		name   string
		target string
		want   PageID
		// unresolved marks a case with no answer. It cannot be inferred from
		// want being zero, because page id 0 is not a page either.
		unresolved bool
	}{
		// 1. an exact vault-relative path
		{name: "exact path with the extension", target: "Gundren.md", want: 1},
		{name: "exact nested path", target: "Party/Tavern.md", want: 2},
		{name: "exact path without the extension", target: "Gundren", want: 1},
		{name: "exact nested path without the extension", target: "Party/Tavern", want: 2},
		{name: "a deep path", target: "Nights/Long/deep/Page", want: 3},

		// 2. an exact basename, with the ambiguity rules
		{name: "basename at the root", target: "Page", want: 5},
		{name: "basename of a nested page", target: "Tavern", want: 6},
		{name: "a path that does not exist falls back to its basename", target: "not/here/Tavern", want: 6},
		{name: "a basename that is also an alias resolves as the page", target: "Secret", want: 9},

		// 3. an alias, case-insensitively
		{name: "alias", target: "The Vault Door", want: 10},
		{name: "alias in a different case", target: "the vault door", want: 10},
		{name: "alias in upper case", target: "THE VAULT DOOR", want: 10},
		{name: "a second alias", target: "Second Alias", want: 10},
		{name: "an alias containing a slash", target: "a/b", want: 11},

		// 2b. a path that does not exist still resolves by basename, because
		// that is what a link author means when they shorten one.
		{name: "a path with a missing component falls back to the basename", target: "No/Such/Page", want: 5},

		// 4. unresolved
		{name: "nothing", target: "Nobody", unresolved: true},
		{name: "an extension that is not a page", target: "map.png", unresolved: true},
		{name: "whitespace only", target: "   ", unresolved: true},

		// Defensive cases: a target written the way a link author might.
		{name: "a leading ./", target: "./Gundren", want: 1},
		{name: "a backslash path", target: `Party\Tavern`, want: 2},
		{name: "surrounding whitespace", target: "  Gundren  ", want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := r.Resolve(tc.target)
			if tc.unresolved {
				if ok {
					t.Errorf("Resolve(%q) = %d, want unresolved", tc.target, got)
				}
				return
			}
			if !ok {
				t.Fatalf("Resolve(%q) = %d, unresolved; want %d", tc.target, got, tc.want)
			}
			if got != tc.want {
				t.Errorf("Resolve(%q) = %d, want %d", tc.target, got, tc.want)
			}
		})
	}
}

// TestResolutionIsDeterministic is the property behind the tie-breaks: the
// answer cannot depend on the order the pages were indexed, because the indexer
// gets them from a query whose order is not guaranteed.
func TestResolutionIsDeterministic(t *testing.T) {
	t.Parallel()
	pages := []PageKey{
		{ID: 6, Path: "Tavern.md"},
		{ID: 7, Path: "World/Tavern.md"},
		{ID: 8, Path: "World/inn/Tavern.md"},
		{ID: 12, Path: "World/b/Tavern.md", Aliases: []string{"Inn"}},
		{ID: 13, Path: "World/a/Tavern.md", Aliases: []string{"Inn"}},
	}
	want, ok := NewResolver(pages).Resolve("Tavern")
	if !ok {
		t.Fatal("Tavern did not resolve")
	}
	// Every rotation of the same pages, and the reversal, must agree.
	for shift := range len(pages) {
		rotated := make([]PageKey, 0, len(pages))
		rotated = append(rotated, pages[shift:]...)
		rotated = append(rotated, pages[:shift]...)
		if got, ok := NewResolver(rotated).Resolve("Tavern"); !ok || got != want {
			t.Errorf("rotating the pages by %d resolved Tavern to %d, want %d", shift, got, want)
		}
	}
	reversed := make([]PageKey, 0, len(pages))
	for i := len(pages) - 1; i >= 0; i-- {
		reversed = append(reversed, pages[i])
	}
	if got, ok := NewResolver(reversed).Resolve("Tavern"); !ok || got != want {
		t.Errorf("reversing the pages resolved Tavern to %d, want %d", got, want)
	}
	// The alias tie is the same rule: the shortest path, then the smallest.
	alias, ok := NewResolver(pages).Resolve("inn")
	if !ok {
		t.Fatal("the alias did not resolve")
	}
	if alias != 13 {
		t.Errorf("the alias tie resolved to %d, want 13 (World/a/Tavern.md)", alias)
	}
}

// TestResolutionTieBreakRules states the two rules on their own, so a change to
// one of them cannot hide behind the other.
func TestResolutionTieBreakRules(t *testing.T) {
	t.Parallel()
	// Shortest path wins: `T.md` is shorter than `deep/dir/T.md` even though
	// the longer one sorts first.
	if got, _ := NewResolver([]PageKey{
		{ID: 1, Path: "deep/dir/T.md"},
		{ID: 2, Path: "T.md"},
	}).Resolve("T"); got != 2 {
		t.Errorf("the shortest path did not win: got %d, want 2", got)
	}
	// On equal length, the lexicographically smaller path wins.
	if got, _ := NewResolver([]PageKey{
		{ID: 1, Path: "b/T.md"},
		{ID: 2, Path: "a/T.md"},
	}).Resolve("T"); got != 2 {
		t.Errorf("the lexicographic tie-break did not apply: got %d, want 2", got)
	}
	// The same length and the same path is the same page, indexed twice.
	r := NewResolver([]PageKey{{ID: 1, Path: "T.md"}, {ID: 1, Path: "T.md"}})
	if got, ok := r.Resolve("T"); !ok || got != 1 {
		t.Errorf("a duplicate page resolved to %d, %v", got, ok)
	}
}

// TestResolutionOfAnEmptyVaultAndOfAnEmptyIndex: both are ordinary states, not
// errors, and both must answer rather than panic.
func TestResolutionOfAnEmptyVaultAndOfAnEmptyIndex(t *testing.T) {
	t.Parallel()
	empty := NewResolver(nil)
	if got, ok := empty.Resolve("Anything"); ok || got != 0 {
		t.Errorf("an empty resolver resolved to %d, %v", got, ok)
	}
	if empty.Len() != 0 {
		t.Errorf("Len = %d, want 0", empty.Len())
	}
	// A page with no path claims nothing, but its aliases still work.
	aliasOnly := NewResolver([]PageKey{{ID: 5, Aliases: []string{"Alias Only"}}})
	if got, ok := aliasOnly.Resolve("Alias Only"); !ok || got != 5 {
		t.Errorf("an alias on a pathless page resolved to %d, %v", got, ok)
	}
	if got, ok := aliasOnly.Resolve("alias only"); !ok || got != 5 {
		t.Errorf("the alias is not case-insensitive: %d, %v", got, ok)
	}
}

// TestSelfLinksAndFragmentsAreNotTargets: a resolver is about pages. A
// `[[#heading]]` names a place inside the page it is written in, and a caller
// that passed the fragment through would look up a page whose name is a
// fragment.
func TestSelfLinksAndFragmentsAreNotTargets(t *testing.T) {
	t.Parallel()
	r := NewResolver([]PageKey{
		{ID: 1, Path: "Gundren.md"},
		{ID: 2, Path: "##odd##.md"},
	})
	// A page name that happens to contain a hash is still a page.
	if got, ok := r.Resolve("##odd##"); !ok || got != 2 {
		t.Errorf("a page named with hashes resolved to %d, %v", got, ok)
	}
	// An empty target is a self-link, and the resolver says so.
	if got, ok := r.Resolve(""); ok || got != 0 {
		t.Errorf("an empty target resolved to %d, %v", got, ok)
	}
}

// TestLinkResolutionFromExtractedLinks ties the two halves together: the links
// the extractor found resolve to the pages a real vault holds. It is the test
// that would catch the extractor and the resolver disagreeing about what a
// target looks like.
func TestLinkResolutionFromExtractedLinks(t *testing.T) {
	t.Parallel()
	renderer := New(Options{})
	// A page written the way a campaign page is written.
	src := []byte("---\naliases:\n  - The Halfling\n---\n\n# Gundren\n\n" +
		"See [[The Vault Door]], [[Tavern|the usual table]], [[Gundren#Flaws]] " +
		"and [[Nothing At All]].\n\n```secret id=abc123abc123\n[[Also Nothing]]\n```\n")
	links, _ := Extract(Parse("Gundren.md", src), renderer)

	res := NewResolver([]PageKey{
		{ID: 10, Path: "World/Ice.md", Aliases: []string{"The Vault Door"}},
		{ID: 6, Path: "Tavern.md"},
		{ID: 1, Path: "Gundren.md", Aliases: []string{"The Halfling"}},
	})
	// Resolution is on Link.Target, which is the page part of TargetRaw: the
	// fragment is a place inside the page, not part of its name.
	want := map[string]PageID{
		"The Vault Door": 10,
		"Tavern":         6,
		"Gundren":        1,
		"Nothing At All": 0,
		"Also Nothing":   0,
	}
	wantRaw := map[string]string{
		"The Vault Door": "The Vault Door",
		// The alias half of a `[[a|b]]` is display text and is not part of
		// the target, which is what store.Link.TargetRaw is for.
		"Tavern":         "Tavern",
		"Gundren":        "Gundren#Flaws",
		"Nothing At All": "Nothing At All",
		"Also Nothing":   "Also Nothing",
	}
	seen := map[string]bool{}
	for _, l := range links.Links {
		seen[l.Target] = true
		if l.TargetRaw != wantRaw[l.Target] {
			t.Errorf("link to %q has TargetRaw %q, want %q", l.Target, l.TargetRaw, wantRaw[l.Target])
		}
		if l.Target == "Tavern" && l.Alias != "the usual table" {
			t.Errorf("the alias of the Tavern link is %q", l.Alias)
		}
		got, ok := res.Resolve(l.Target)
		if got != want[l.Target] {
			t.Errorf("link %q resolved to %d (%v), want %d", l.Target, got, ok, want[l.Target])
		}
		if (got != 0) != ok {
			t.Errorf("link %q: id %d disagrees with the ok flag %v", l.Target, got, ok)
		}
	}
	for target := range want {
		if !seen[target] {
			t.Errorf("the extractor never reported a link to %q", target)
		}
	}
	// The link inside the secret is indexed, and attributed, so that a query
	// filtering on the secret id can drop it.
	var secretLink *Link
	for i := range links.Links {
		if links.Links[i].TargetRaw == "Also Nothing" {
			secretLink = &links.Links[i]
		}
	}
	if secretLink == nil {
		t.Fatal("the link inside the secret was not extracted")
	}
	if secretLink.Span.SecretID != "abc123abc123" {
		t.Errorf("the link inside the secret is attributed to %q", secretLink.Span.SecretID)
	}
}

// TestPathsAreIndexedBothWithAndWithoutTheExtension documents the two keys a
// page claims, because a link author writes one and the filesystem holds the
// other.
func TestPathsAreIndexedBothWithAndWithoutTheExtension(t *testing.T) {
	t.Parallel()
	r := NewResolver([]PageKey{{ID: 1, Path: "a/b/Note.md", Basename: "Note"}})
	paths := r.Paths()
	want := []string{"a/b/Note", "a/b/Note.md"}
	if !sameStrings(paths, want) {
		t.Errorf("indexed paths = %q, want %q", paths, want)
	}
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1", r.Len())
	}
}
