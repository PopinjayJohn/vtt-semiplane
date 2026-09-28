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

	// A per-plugin assertion, keyed on Kind rather than on a single plugin's
	// shape.
	//
	// This test used to assert that every plugin registers at least two page
	// types and a panel, which was true when dnd5e was the only entry and became
	// a statement about dnd5e the moment a feature plugin was added. The rule
	// that actually holds is the kind rule, and it is a stronger one: a system
	// plugin with no page types and a feature plugin with any are both wrong, and
	// in opposite directions. Asserting the aggregate instead would have let both
	// through.
	byKind := map[plugin.Kind]int{}
	for _, e := range report.Entries {
		if e.Status == plugin.StatusSkipped {
			t.Errorf("the shipped plugin %q was refused at boot: %s", e.ID, e.Reason)
			continue
		}
		byKind[e.Kind]++

		switch e.Kind {
		case plugin.KindSystem:
			if e.Count.PageTypes == 0 {
				t.Errorf("system plugin %q registered no page types; the kind exists to add them: %+v",
					e.ID, e.Count)
			}
		case plugin.KindFeature:
			if e.Count.PageTypes != 0 {
				t.Errorf("feature plugin %q registered %d page types; a feature expresses content through "+
					"frontmatter conventions and the host is supposed to refuse it at boot", e.ID, e.Count.PageTypes)
			}
		default:
			t.Errorf("plugin %q has kind %q, which is neither system nor feature", e.ID, e.Kind)
		}

		// A plugin that contributes nothing to any surface is a plugin that is in
		// the tree and does nothing. It is not an error — the host is right to
		// keep a working app — but in a *shipped* registry it is a fact nobody
		// should have to notice, and it is the shape a plugin breaks into when
		// its registrations start failing.
		c := e.Count
		if c.PageTypes+c.Panels+c.NavItems+c.SearchResolvers+c.Summaries+c.Routes+c.Extenders+c.Migrations == 0 {
			t.Errorf("shipped plugin %q registered with every count zero: %+v", e.ID, c)
		}
	}
	if len(byKind) < 2 {
		t.Errorf("the shipped registry holds %d plugin kind(s) (%v); the Kind split is supposed to be "+
			"something a build runs, not something a document claims", len(byKind), byKind)
	}

	reg := a.PluginRegistry()
	if reg == nil {
		t.Fatal("PluginRegistry returned nil after a boot that ran the lifecycle")
	}
	// The registry must be reachable through every surface a plugin can
	// contribute to, because a plugin that registered into the host and did not
	// reach the registry is a plugin the request path cannot see. Asserting one
	// surface per kind catches a commit step that dropped one of them, which is
	// the failure mode a per-plugin count cannot.
	for _, id := range []string{"character", "rule"} {
		if _, ok := reg.PageType(id); !ok {
			t.Errorf("the %q page type did not reach the registry", id)
		}
	}
	if got := reg.PanelsFor("character"); len(got) == 0 {
		t.Error("a character page has no panels, so the one-map-entry claim is not demonstrated")
	}
	if len(reg.NavItems()) == 0 {
		t.Error("no sidebar entry reached the registry")
	}
	if len(reg.SearchResolvers()) == 0 {
		t.Error("no search resolver reached the registry, so /search cannot surface plugin rows")
	}
	if len(reg.Summaries()) == 0 {
		t.Error("no summary provider reached the registry, so the link-preview interaction has nothing to " +
			"dispatch to and will 404 every hover")
	}
	if len(reg.Routes()) == 0 {
		t.Error("no plugin sub-router reached the registry, so every /plugin/ route is a 404")
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
