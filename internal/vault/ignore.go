package vault

import "strings"

// ignoredDirs are directory names the walk never descends into and the watcher
// never registers, at any depth.
//
// They are the app's own state and other tools' state. None of it is campaign
// content, and indexing it would put a database file and a copy of the vault's
// own ignore rules into the vault's search index.
var ignoredDirs = map[string]bool{
	HiddenDir:      true, // our own database, lock, backups and temp files
	".obsidian":    true, // Obsidian's workspace and plugin state
	".trash":       true, // Obsidian's deletions
	".git":         true,
	"node_modules": true,
}

// ignoredSuffixes are file names the app's own machinery produces or that a
// SQLite database leaves behind mid-transaction.
//
// A -wal or -shm file changes on every checkpoint, so watching one would index
// continuously. A temp file changes twice per write, and the watcher must never
// report the app's own work back to the app.
var ignoredSuffixes = []string{
	tempSuffix,
	".db-wal",
	".db-shm",
	".db-journal",
}

// ignoredDirName reports whether a directory should be skipped, by base name.
func ignoredDirName(name string) bool { return ignoredDirs[name] }

// ignoredFileName reports whether a file should be skipped, by base name.
func ignoredFileName(name string) bool {
	for _, suffix := range ignoredSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// ignoredRel reports whether a vault-relative path is skipped, by any element.
// The walker consults it per entry; the watcher consults it per event. Both use
// the whole relative path so a nested .git is skipped exactly as a root one is.
func ignoredRel(rel string) bool {
	if rel == "" || rel == "." {
		return false
	}
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		if i == len(parts)-1 {
			if ignoredFileName(part) {
				return true
			}
			continue
		}
		if ignoredDirName(part) {
			return true
		}
	}
	return false
}
