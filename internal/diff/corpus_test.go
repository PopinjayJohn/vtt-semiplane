package diff

// Test corpus: representative vtt-semiplane vault markdown, plus the fixtures
// that shape an edit rather than its content. Derived from the library spike's
// corpus, trimmed to what this package's tests actually assert on.
//
// The content matters less than its shape. The markdown below is what
// internal/md actually consumes — wikilinks, callouts, tables, mermaid, code
// fences, and a ```secret fence in the exact form AGENTS.md §6 specifies — so
// a passing test is a statement about the input this will be given rather than
// about a generator that happened to be convenient.

import (
	"fmt"
	"strings"
)

var npcNames = []string{
	"Gundren Rockjaw", "Sildar Hallwinter", "Marlow Vantress", "Thessaly Greymantle",
	"Bramwell Ashdown", "Ophira Delmarc", "Kestrel of the Fen", "Aldric Thorn",
	"Wilhelmina Vance", "Corvin Blackbriar", "Ysolt Fairweather", "Dagoneth Ilm",
}

var placeNames = []string{
	"Neverwinter", "Phandalin", "Waterdeep", "Icewind Dale", "Brimstone",
	"The Sunless Citadel", "Red Larch", "Thundertree", "Locathah", "Moonshae",
	"Yartar", "Tomb of Trials", "Gloomhaigh", "Mistford",
}

var factionNames = []string{
	"the Harpers", "the Zhentarim", "the Order of the Flame", "the Gilded Rose",
	"the Masked Council", "the Purple Dragons", "the Xanathar Cult",
}

var godNames = []string{
	"Mystra", "Tymora", "Lathander", "Selune", "Mask", "Oghma", "Tempest",
	"Chauntea", "Bahamut", "Tiamat", "Moradin", "Lolth",
}

func pick(i int, kind string) string {
	switch kind {
	case "npc":
		return npcNames[i%len(npcNames)]
	case "place":
		return placeNames[i%len(placeNames)]
	case "faction":
		return factionNames[i%len(factionNames)]
	default:
		return godNames[i%len(godNames)]
	}
}

func slug(s string) string {
	return strings.NewReplacer(" ", "-", "—", "-").Replace(strings.ToLower(s))
}

func prose(i int) string {
	return fmt.Sprintf("%s keeps a ledger in the basement of the [%s](%s) and pays %s in copper "+
		"for quiet work. See also [[%s]] and the [[%s|cellar ledger]] recovered in session %d.",
		pick(i, "npc"), pick(i, "place"), slug(pick(i, "place")),
		pick(i+1, "faction"), pick(i, "place"), pick(i+2, "npc"), 3+i%11)
}

func callout(i int) string {
	return fmt.Sprintf("> [!warning] %s is watching\n> The %s route is closed until %s takes the toll.\n",
		pick(i, "faction"), pick(i, "place"), pick(i, "npc"))
}

func listBlock(i int) string {
	var b strings.Builder
	for k := 0; k < 5; k++ {
		n := i + k
		fmt.Fprintf(&b, "- **%s** — %d gp, %s, `weight %d lb`\n",
			pick(n, "npc"), 25*(n%17+1), pick(n, "place"), 3*(n%9+1))
	}
	return b.String()
}

func codeFence(i int) string {
	return fmt.Sprintf("```yaml\nid: encounter-%03d\nname: %s\nparty_level: %d\n"+
		"hazards:\n  - id: h%d\n    kind: trap\n    dc: %d\n```\n",
		i, pick(i, "place"), 3+i%6, i, 12+i%9)
}

func table(i int) string {
	return fmt.Sprintf("| Location | Watch | Signal |\n|---|---|---|\n| %s | %s | red |\n| %s | %s | none |\n",
		pick(i, "place"), pick(i, "npc"), pick(i+1, "place"), pick(i+2, "npc"))
}

func secretFence(i int) string {
	// The shape from AGENTS.md §6. title is quoted because it has a space.
	return fmt.Sprintf("```secret id=%012x visibility=dm author=dm created=2026-04-%02dT18:30:00Z title=\"The %s Ledger\"\n"+
		"The real ledger records a second key, held by %s, and the vault combination %04d-%02d.\n```\n",
		0xabc000000000+i*7919, 1+i%28, pick(i, "place"), pick(i+1, "npc"), 1000+i%8999, i%100)
}

func mermaid(i int) string {
	return fmt.Sprintf("```mermaid\ngraph TD\n  A[%s] --> B[%s]\n  B --> C[%s]\n```\n",
		pick(i, "npc"), pick(i+1, "place"), pick(i+2, "faction"))
}

// wikiPage is one page with roughly the given number of body sections.
func wikiPage(path string, sections int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "---\ntype: lore\ntitle: %s\ntags: [%s, lore, session-14]\nupdated: 2026-04-11\n---\n\n",
		strings.TrimSuffix(strings.TrimSuffix(path, ".md"), "/"), pick(len(path), "npc"))
	fmt.Fprintf(&b, "# %s\n\n", pick(len(path), "place"))
	for s := 0; s < sections; s++ {
		i := len(path)*13 + s*7
		fmt.Fprintf(&b, "## %d. %s\n\n", s+1, pick(i, "npc"))
		fmt.Fprintf(&b, "%s\n\n", prose(i))
		b.WriteString("### Notes\n\n")
		fmt.Fprintf(&b, "- linked: [[%s]]\n- linked: [[%s#Notes]]\n- tagged: #lore/%s\n\n",
			pick(i+1, "place"), pick(i+2, "npc"), slug(pick(i, "place")))
		if s%3 == 1 {
			b.WriteString(callout(i) + "\n")
		}
		if s%4 == 2 {
			b.WriteString(listBlock(i) + "\n")
		}
		if s%5 == 3 {
			b.WriteString(codeFence(i) + "\n")
		}
		if s%6 == 4 {
			b.WriteString(table(i) + "\n")
		}
		if s%7 == 5 {
			b.WriteString(mermaid(i) + "\n")
		}
		if s%9 == 7 {
			b.WriteString(secretFence(i))
		}
	}
	return b.String()
}

// toCRLF is the same page with Windows line endings, as a vault authored on a
// desktop would have it. It is the input that makes a terminator-stripping
// comparison a correctness requirement rather than a preference.
func toCRLF(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

// smallEdit changes exactly one line, deep inside the page.
//
// The two branches are the two shapes a real page has at depth: a list item in
// the medium page and a table row in the pathological one. A mutator that only
// matched one of them would silently turn a 400 KiB benchmark into a no-op,
// which reads as a very fast diff rather than as a broken fixture.
func smallEdit(s string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		crlf := strings.HasSuffix(lines[i], "\r")
		body := strings.TrimSuffix(lines[i], "\r")
		switch {
		case strings.HasPrefix(body, "- **"):
			body = strings.Replace(body, "—", "— (restocked)", 1)
		case strings.HasPrefix(body, "|"):
			body += " (restocked)"
		default:
			continue
		}
		if crlf {
			body += "\r"
		}
		lines[i] = body
		break
	}
	return strings.Join(lines, "\n")
}

// midLineEdit changes a single word inside a long line. A line-based diff must
// still report the whole line as a delete and an insert, never a byte range.
func midLineEdit(s string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		if strings.HasPrefix(lines[i], "| ") && strings.Contains(lines[i], "| red |") {
			lines[i] = strings.Replace(lines[i], "red", "crimson", 1)
			break
		}
	}
	return strings.Join(lines, "\n")
}

// blockMove relocates a contiguous run of lines, which is the shape a player
// produces when they drag a section under a different parent heading and which
// a prefix/suffix trim cannot help with.
func blockMove(s string) string {
	lines := strings.Split(s, "\n")
	n := len(lines)
	from, size := n/3, 17
	block := append([]string(nil), lines[from:from+size]...)
	rest := append(append([]string(nil), lines[:from]...), lines[from+size:]...)
	shift := 2*n/3 - size
	out := append(append([]string(nil), rest[:shift]...), block...)
	return strings.Join(append(out, rest[shift:]...), "\n")
}

// different is a wholly unrelated page of comparable length.
func different() string { return wikiPage("world/zzz-unrelated-notes", 40) }

// pathological is a page of at least 400 KiB. Long lines, high repetition,
// near-duplicate rows: the shapes that make a naive diff quadratic.
func pathological() string {
	var b strings.Builder
	b.WriteString("---\ntype: session\ntitle: Session Log Compendium\ntags: [session]\n---\n\n")
	b.WriteString("# Session Log Compendium\n\n")
	for i := 0; b.Len() < 400*1024; i += 4 {
		fmt.Fprintf(&b, "## Session %d — %s\n\n", i/4+1, pick(i, "npc"))
		b.WriteString("| turn | actor | target | outcome | damage | notes |\n|---|---|---|---|---|---|\n")
		for k := 0; k < 4; k++ {
			fmt.Fprintf(&b, "| %d | [[%s]] | %s | hit | %d | %s |\n",
				k, pick(i+k, "npc"), pick(i+k+1, "place"), 3+k, prose(i+k))
		}
		fmt.Fprintf(&b, "\n> [!note] Recap %d\n> %s\n\n", i, prose(i+1))
		if i%16 == 7 {
			b.WriteString(secretFence(i))
		}
	}
	return b.String()
}

// manySmallEdits is what a lost optimistic-concurrency race actually looks
// like: two people each fixed a few things in the same session log.
func manySmallEdits(s string, n int) string {
	lines := strings.Split(s, "\n")
	step := len(lines) / (n + 1)
	for i := 0; i < n; i++ {
		if at := step * (i + 1); at < len(lines) {
			lines[at] += fmt.Sprintf("  (amended %c)", 'a'+i)
		}
	}
	return strings.Join(lines, "\n")
}

// halfRewritten replaces every other body line, so half the page is new.
func halfRewritten(s string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		if i%2 == 0 && lines[i] != "" {
			lines[i] = "> " + lines[i]
		}
	}
	return strings.Join(lines, "\n")
}

// firstLines is the first n lines of s as a file of their own, terminators
// included, which is what a truncation looks like from the other side.
func firstLines(s string, n int) string {
	parts := strings.SplitAfter(s, "\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if n > len(parts) {
		n = len(parts)
	}
	return strings.Join(parts[:n], "")
}

// fixtures are the shapes the conflict page actually has to render. Every one
// of them is a documented behaviour rather than a regression: a no-op, a
// single edit, a moved block, a wholly-different page, either side empty, both
// empty, a trailing-newline difference and a CRLF difference.
func fixtures() []struct {
	name string
	a, b string
} {
	big, med := pathological(), wikiPage("world/neverwinter-faction-web", 30)
	return []struct {
		name string
		a, b string
	}{
		{"no-change/small", med, med},
		{"no-change/pathological", big, big},
		{"small-edit-in-large", med, smallEdit(med)},
		{"small-edit-in-pathological", big, smallEdit(big)},
		{"block-move", med, blockMove(med)},
		{"block-move-pathological", big, blockMove(big)},
		{"entirely-different", med, different()},
		{"empty-to-content", "", med},
		{"content-to-empty", med, ""},
		{"both-empty", "", ""},
		{"crlf-vs-lf", med, toCRLF(med)},
		{"crlf-vs-crlf-small-edit", toCRLF(med), smallEdit(toCRLF(med))},
		{"no-trailing-newline", "x\ny\nz", "x\ny\nZ"},
		{"append-only", med, med + "\nOne more line.\n"},
		{"truncate-only", med, "x\ny\nz\n"},
		{"many-small-edits", big, manySmallEdits(big, 20)},
		{"half-rewritten", big, halfRewritten(big)},
	}
}
