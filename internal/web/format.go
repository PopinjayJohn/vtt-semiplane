package web

import (
	"strconv"
	"strings"
)

// itoa is strconv.Itoa, for the places a template wants a number.
func itoa(n int) string { return strconv.Itoa(n) }

// urlQueryEscape percent-encodes a value for one query parameter.
//
// The templates use it wherever a term or a tag goes back into a URL, so a value
// containing a space, an ampersand or a quote cannot break out of the attribute
// it was written into.
func urlQueryEscape(s string) string {
	return strings.NewReplacer(
		"%", "%25", "&", "%26", "?", "%3F", "#", "%23", " ", "%20",
		"\"", "%22", "'", "%27", "<", "%3C", ">", "%3E",
	).Replace(s)
}

// plural is the one-word-or-many-word choice every count in the layout needs.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
