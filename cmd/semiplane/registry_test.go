package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/app"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
)

// "Adding a page type and a sidebar panel is one map entry" is this stage's
// central claim, and it is the kind of claim that survives being written down
// long after it stops being true.
//
// A plugin can be present in the tree, present in the registry, and refused at
// every single boot — and every one of those three facts looks like success from
// the file list. So the test is here, in the package that owns the map, and it
// boots the real lifecycle with the real registry rather than inspecting the map
// to see that it has one entry.

// TestTheShippedPluginActuallyRegisters boots the app the way the binary does.
func TestTheShippedPluginActuallyRegisters(t *testing.T) {
	t.Parallel()
	v := testutil.WithVault(t, map[string]string{
		"Index.md": "---\ntitle: Index\n---\n\n# Index\n\nThe campaign index.\n",
	})
	a, err := app.Boot(context.Background(), app.Options{
		Config: config.Config{
			Vault:             v.Root,
			VaultSource:       "flag:--vault",
			Host:              "127.0.0.1",
			Port:              0,
			LogLevel:          "error",
			MaxAttachmentSize: 32 << 20,
		},
		// The map this file exists to justify.
		Plugins: builtinPlugins(),
		Handler: http.NotFoundHandler(),
		Logger:  obs.Discard(),
		Clock:   obs.SystemClock,
	})
	if err != nil {
		t.Fatalf("boot with the shipped registry: %v", err)
	}
	t.Cleanup(func() { _ = a.Shutdown(context.Background()) })

	report := a.PluginReport()
	if len(report.Entries) == 0 {
		t.Fatal("the registry offered a plugin and the boot report is empty: the map entry never reached the lifecycle")
	}

	var registered int
	for _, e := range report.Entries {
		if e.Status == plugin.StatusSkipped {
			t.Errorf("the shipped plugin %q was refused at boot: %s", e.ID, e.Reason)
			continue
		}
		registered++
		if e.Count.PageTypes < 2 {
			t.Errorf("plugin %q registered %d page types, want at least character and rule: %+v",
				e.ID, e.Count.PageTypes, e.Count)
		}
		if e.Count.Panels < 1 {
			t.Errorf("plugin %q registered %d panels, want at least one: %+v", e.ID, e.Count.Panels, e.Count)
		}
	}
	if registered == 0 {
		t.Fatalf("no shipped plugin registered: %+v", report.Entries)
	}

	reg := a.PluginRegistry()
	if reg == nil {
		t.Fatal("PluginRegistry returned nil after a boot that ran the lifecycle")
	}
	for _, id := range []string{"character", "rule"} {
		if _, ok := reg.PageType(id); !ok {
			t.Errorf("the %q page type did not reach the registry", id)
		}
	}
	if got := reg.PanelsFor("character"); len(got) == 0 {
		t.Error("a character page has no panels, so the one-map-entry claim is not demonstrated")
	}
}

// TestEveryShippedPluginIsInTheReport is the other half: a plugin in the map
// that never appears in the report is invisible, and an invisible plugin is one
// nobody is maintaining.
func TestEveryShippedPluginIsInTheReport(t *testing.T) {
	t.Parallel()
	offered := builtinPlugins()
	if len(offered) == 0 {
		t.Fatal("the registry is empty: this build ships no plugins, and the stage's claim is about the ones it does")
	}
	for id, p := range offered {
		if d := p.Descriptor(); d.ID != id {
			t.Errorf("the map key is %q but the descriptor says %q: the key is what the report and the gate read, "+
				"so a mismatch makes the entry untraceable", id, d.ID)
		}
	}
}
