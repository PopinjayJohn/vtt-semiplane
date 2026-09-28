package web

import "github.com/a-h/templ"

// PreRendered wraps HTML that md.Renderer produced.
//
// This function and Escaped are the ONLY places in the codebase that call
// templ.Raw, and TestOnlyThisPackageMarksHTMLRaw walks the tree to keep it that
// way. The rule is §2.6: never mark a string that came out of a vault as raw.
// Everything a vault file contributes to a response goes through md first, which
// escapes by construction and never enables goldmark's html.WithUnsafe, so the
// string that arrives here is HTML this application wrote — and nothing else
// may be passed to it.
//
// A caller holding a vault string and wanting it in a document passes it to
// templ as a string, which escapes it. There is no second, convenient path, and
// that is the only thing making this safe: the funnel is narrow because it is
// checked, not because it is documented.
func PreRendered(html string) templ.Component {
	return templ.Raw(html)
}

// Escaped wraps a string that another package in this codebase has already
// escaped for HTML.
//
// It exists for the search snippets, which search.Query escapes at the point it
// builds them so that there is one place that can get it wrong rather than one
// per render site. Marking them raw is therefore correct and letting templ
// escape them again would be a bug: a snippet containing an ampersand would
// reach the reader as "&amp;".
//
// It is not a licence to pass anything through unescaped. A string reaches this
// function only from a package that called html.EscapeString on it, and the test
// that greps for templ.Raw keeps the call sites to two named functions.
func Escaped(html string) templ.Component {
	return templ.Raw(html)
}
