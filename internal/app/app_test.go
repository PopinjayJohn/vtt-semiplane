package app

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestInfoFillsEveryField(t *testing.T) {
	info := Info()
	if info.Version == "" || info.Commit == "" || info.Date == "" || info.Go == "" {
		t.Fatalf("build info is incomplete: %+v", info)
	}
	if !strings.HasPrefix(info.Go, "go1.") {
		t.Errorf("Go = %q", info.Go)
	}
}

func TestCommitFallsBackToTheVCSStamp(t *testing.T) {
	if Commit != "none" {
		t.Skip("linked with an explicit commit")
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build info available")
	}
	var stamped string
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			stamped = s.Value
		}
	}
	if stamped == "" {
		t.Skip("not a vcs build")
	}
	if got := Info().Commit; got != stamped {
		t.Errorf("Commit = %q, want the vcs revision %q", got, stamped)
	}
}

func TestStringIsOneLine(t *testing.T) {
	s := Info().String()
	if strings.ContainsAny(s, "\n\r") {
		t.Errorf("String is multi-line: %q", s)
	}
	if !strings.Contains(s, Info().Version) {
		t.Errorf("String does not carry the version: %q", s)
	}
}
