package app

import (
	"runtime"
	"runtime/debug"
)

// Build metadata, injected at link time:
//
//	-ldflags "-X github.com/PopinjayJohn/vtt-semiplane/internal/app.Version=v1.2.3 \
//	          -X .../app.Commit=abc1234 \
//	          -X .../app.Date=2026-09-28T10:04:11Z"
var (
	// Version is the release version, or "dev" for a local build.
	Version = "dev"
	// Commit is the git commit, or "none" for a local build.
	Commit = "none"
	// Date is the build date, or "unknown".
	Date = "unknown"
)

// BuildInfo is the metadata block printed by `semiplane version` and included
// in the startup banner and the /_/readyz response.
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Go      string `json:"go"`
}

// Info returns the build metadata. When Commit is "none" it falls back to the
// VCS stamp the Go toolchain embeds, so a `go build` without ldflags still
// reports which revision it came from.
func Info() BuildInfo {
	info := BuildInfo{Version: Version, Commit: Commit, Date: Date, Go: runtime.Version()}
	if info.Commit == "none" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					info.Commit = s.Value
				}
			}
		}
	}
	return info
}

// String renders the build metadata one line per field, for the CLI.
func (b BuildInfo) String() string {
	return b.Version + " (" + b.Commit + ", " + b.Date + ", " + b.Go + ")"
}
