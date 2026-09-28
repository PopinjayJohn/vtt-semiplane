// Package sample holds the embedded sample campaign, extracted on first boot.
//
// The campaign is written as ordinary Obsidian-compatible markdown so it stays
// useful in a vault that is also opened in Obsidian, and it is the fixture the
// whole secret-leak suite runs against. Extraction is non-clobbering: an
// existing file is never overwritten.

package sample
