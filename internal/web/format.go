package web

import (
	"strconv"
)

// itoa is strconv.Itoa, for the places a template wants a number.
func itoa(n int) string { return strconv.Itoa(n) }

// plural is the one-word-or-many-word choice every count in the layout needs.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
