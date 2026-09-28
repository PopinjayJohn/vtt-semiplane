package example

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/go-chi/chi/v5"
)

// The evidence, in two layers that assert the same claims at different heights.
//
// The low layer runs the host's own rules — plugin.CheckReservedPageType and
// plugin.CheckReservedRoute — and is therefore about the *rule*: does it fire,
// and does its reason name the thing that was wrong. The high layer boots a real
// registry with plugin.Load and is about the *host*: does the boot report record
// that refusal with the same specificity, and does the registry hold nothing the
// refused plugin contributed.
//
// Neither layer asserts only that a plugin was refused. Asserting that would
// pass against a host that refused everything for one unstated reason, which is
// exactly the shape of a boundary that is documented rather than enforced. Every
// assertion below is on the reason's content, on the registry being empty, or on
// the report having a line at all.

// demonstration is one example, the host check it is built to trip, and what the
// report has to say about it.
type demonstration struct {
	// name is the case, named for what the plugin does.
	name string
	// aim is the host check this example is built to trip, so a failure says
	// which check should have fired rather than printing a list diff.
	aim string
	// construct builds exactly one example.
	construct func() plugin.Plugin
	// claims is every reserved-name claim this example makes, and what the
	// reserved-name rule must do with each.
	claims []claim
	// alone reports whether loading this example on its own must produce a
	// skipped report line. False for the collision example, which needs a second
	// plugin to collide with and is therefore a working plugin by itself —
	// TestACollidingPageTypeDisablesOnlyThatPlugin is where it is refused.
	alone bool
	// reportNames are the substrings the boot report's reason must carry for
	// this example. They are stated here rather than derived from the claims
	// because the host reports the *first* fault it found, not every fault, so a
	// plugin that breaks three rules gets one line naming one of them. What
	// that line says is still specific, and that is what is asserted.
	reportNames []string
	// quotesRule is the subject of the claim whose rule produced the reported
	// line, and asserting that the line quotes that rule verbatim is the
	// strongest form of "the reason is the right reason": there is no second
	// wording anywhere in the path. Empty where the line came from a rule with
	// no exported predicate, or from a rule other than the reserved-name ones —
	// see the last row, where the host catches the kind violation before it
	// ever mounts a route.
	quotesRule string
}

// demonstrations is all five examples.
//
// The table includes the two whose refusal has no exported predicate. For
// those, every reserved-name claim is recorded as *not* refused, and that is the
// assertion: it pins the refusal to a different rule by showing this one admits
// the example, so a reason in a boot report cannot have come from reserved.go
// when the real cause was a kind violation or a collision.
var demonstrations = []demonstration{
	{
		name:      "system claiming a reserved page type without the capability",
		aim:       "plugin.CheckReservedPageType",
		construct: ReservedPageTypeWithoutCapability,
		claims: []claim{{
			subject:     reservedPageType,
			check:       pageTypeRule(reservedPageType),
			refused:     true,
			mustName:    []string{"reserved page type", `"character"`, `"character_sheet"`, "plugin system"},
			mustNotName: []string{"reserved route", "plugin feature"},
			repair: func(_ plugin.Kind, g plugin.Capabilities) (plugin.Kind, plugin.Capabilities) {
				return plugin.KindSystem, g.With(plugin.CapCharacterSheet)
			},
		}},
		alone:       true,
		reportNames: []string{"reserved page type", `"character"`, `"character_sheet"`, "plugin system"},
		quotesRule:  reservedPageType,
	},
	{
		name:      "feature registering a reserved route while holding the capability",
		aim:       "plugin.CheckReservedRoute",
		construct: ReservedRouteAsFeature,
		claims: []claim{{
			subject:     reservedRoute,
			check:       routeRule(reservedRoute),
			refused:     true,
			mustName:    []string{"plugin feature", "register the route", `"/map"`, `"map" segment`, `"maps" capability`},
			mustNotName: []string{"reserved page type", "plugin system may not"},
			repair: func(_ plugin.Kind, g plugin.Capabilities) (plugin.Kind, plugin.Capabilities) {
				return plugin.KindSystem, g
			},
		}},
		alone:       true,
		reportNames: []string{"plugin feature", "register the route", `"/map"`, `"map" segment`, `"maps" capability`},
		quotesRule:  reservedRoute,
	},
	{
		name:      "feature declaring a page type",
		aim:       "the host's KindFeature rule, which has no exported predicate",
		construct: FeatureDeclaringPageTypes,
		claims: []claim{{
			// The id is held by nothing, so the reserved-name rule admits it and
			// the kind of the plugin claiming it is the whole of the problem.
			subject: featurePageType,
			check:   pageTypeRule(featurePageType),
		}},
		alone: true,
		// The rule's own text names no plugin and no id: host.fault deliberately
		// does not prefix one, because a second "plugin <id>:" in front of a
		// reserved-name reason is stutter. Entry.ID is the column that says which
		// plugin this line is about.
		reportNames: []string{"may not declare page types", "feature"},
	},
	{
		name:      "system whose page type collides with another plugin's",
		aim:       "the registry's collision check, which has no exported predicate",
		construct: CollidingPlugin,
		claims: []claim{
			{subject: collisionPageType, check: pageTypeRule(collisionPageType)},
			{subject: "/run-example", check: routeRule("/run-example")},
		},
		alone: false,
	},
	{
		name:      "feature breaking three rules at once",
		aim:       "both reserved-name predicates, plus the KindFeature rule",
		construct: TwoBadThings,
		claims: []claim{
			{
				subject:     reservedPageType,
				check:       pageTypeRule(reservedPageType),
				refused:     true,
				mustName:    []string{"reserved page type", `"character"`, `"character_sheet"`, "plugin feature"},
				mustNotName: []string{"register the route"},
				repair: func(_ plugin.Kind, g plugin.Capabilities) (plugin.Kind, plugin.Capabilities) {
					// Wrong twice over — the wrong kind *and* the missing grant —
					// so the repair has to be both, which is the point of this row.
					return plugin.KindSystem, g.With(plugin.CapCharacterSheet)
				},
			},
			{
				subject:     reservedRoute,
				check:       routeRule(reservedRoute),
				refused:     true,
				mustName:    []string{"register the route", `"/map"`, `"maps"`, "plugin feature"},
				mustNotName: []string{"reserved page type"},
				repair: func(_ plugin.Kind, g plugin.Capabilities) (plugin.Kind, plugin.Capabilities) {
					return plugin.KindSystem, g
				},
			},
		},
		alone: true,
		// The host reports the first fault it found, and a feature that declares
		// page types is caught before any route is even mounted, so the line
		// names the kind rule. That the *other two* violations are real is
		// proved above, against both rules, and is not visible in this one line.
		reportNames: []string{"may not declare page types", "feature"},
	},
}

// claim is one reserved-name claim, and what the host's rule must do with it.
type claim struct {
	// subject is the page-type id or the route pattern being claimed, so a
	// failure names the claim and not just the plugin.
	subject string
	// check is the host's own predicate, called exactly as the host calls it: the
	// plugin's kind and the capabilities it was granted. The test runs the real
	// rule rather than a reimplementation of it, because two implementations of
	// "may this plugin claim that" is the exact failure reserved.go exists to
	// prevent.
	check func(kind plugin.Kind, granted plugin.Capabilities) error
	// refused is whether this rule must reject the claim. False for the two
	// examples aimed at rules with no exported predicate, and that is the whole
	// assertion in those rows.
	refused bool
	// mustName are substrings the reason has to carry. These are what a host
	// refusing everything for one unstated reason would not produce.
	mustName []string
	// mustNotName are substrings the reason must not carry. These are what make
	// swapping two checks' messages fail this test.
	mustNotName []string
	// repair yields the smallest change to the plugin that makes this rule
	// accept, so the test can show the refusal was caused by the property it is
	// aimed at and by nothing else.
	repair func(kind plugin.Kind, granted plugin.Capabilities) (plugin.Kind, plugin.Capabilities)
}

// pageTypeRule binds the reserved page-type predicate to one id.
func pageTypeRule(id string) func(plugin.Kind, plugin.Capabilities) error {
	return func(k plugin.Kind, g plugin.Capabilities) error {
		return plugin.CheckReservedPageType(id, k, g)
	}
}

// routeRule binds the reserved route predicate to one pattern.
func routeRule(pattern string) func(plugin.Kind, plugin.Capabilities) error {
	return func(k plugin.Kind, g plugin.Capabilities) error {
		return plugin.CheckReservedRoute(pattern, k, g)
	}
}

// TestEachExampleIsRefusedWithItsOwnReason is the central claim about the rule:
// each example is refused, and each refusal names the thing that was wrong.
//
// Three assertions together are what make this worth more than a table of
// booleans. The rule must refuse, or nothing is demonstrated. The reason must
// name the specific id, the specific capability and the specific kind, and must
// *not* name the vocabulary of the other check, or two rules could be swapped and
// the test would not notice. And correcting the one property the claim is aimed
// at must be enough to satisfy the rule, or the refusal was caused by something
// this test did not intend to demonstrate.
func TestEachExampleIsRefusedWithItsOwnReason(t *testing.T) {
	t.Parallel()

	// Subtests run in sequence: the distinctness assertion below needs every
	// reason at once, and a shared map written from parallel subtests is a race,
	// not evidence.
	reasons := make([]string, len(demonstrations))

	for i, tc := range demonstrations {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.construct()
			d := p.Descriptor()
			if err := d.ValidateID(); err != nil {
				t.Fatalf("the example declares an unusable id, so a host could refuse it for a reason that has nothing to do with the demonstration: %v", err)
			}
			if d.ID != ID {
				t.Fatalf("descriptor id = %q, want %q", d.ID, ID)
			}
			granted := grantedFor(t, p)

			var said []string
			for _, c := range tc.claims {
				err := c.check(d.Kind, granted)
				if !c.refused {
					if err != nil {
						t.Errorf("%s refuses %q, so this example is not isolated to the check it is aimed at: %v", tc.aim, c.subject, err)
					}
					continue
				}
				if err == nil {
					t.Fatalf("%s admits %q: %s is a %s granted %v, and this rule exists to refuse exactly that",
						tc.aim, c.subject, d.ID, d.Kind, granted.List())
				}
				for _, want := range c.mustName {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("%s refused %q without saying %q:\n  %v", tc.aim, c.subject, want, err)
					}
				}
				for _, unwanted := range c.mustNotName {
					if strings.Contains(err.Error(), unwanted) {
						t.Errorf("%s refused %q with the vocabulary of another check (%q):\n  %v", tc.aim, c.subject, unwanted, err)
					}
				}
				kind, caps := c.repair(d.Kind, granted)
				if still := c.check(kind, caps); still != nil {
					t.Errorf("%s still refuses %q after correcting the one property it is aimed at: %v", tc.aim, c.subject, still)
				}
				said = append(said, err.Error())
			}
			reasons[i] = strings.Join(said, "; ")
		})
	}

	// Two examples refused with identical wording means one of them is being
	// refused by a check the other does not trip, which is the whole reason for
	// demanding a specific reason in the first place. The two examples sharing a
	// rule — both features declaring page types — are compared by name below
	// rather than here, because a rule that is consistent is a rule working.
	seen := make(map[string]string, len(reasons))
	for i, tc := range demonstrations {
		if reasons[i] == "" {
			continue
		}
		if other, dup := seen[reasons[i]]; dup {
			t.Errorf("%q and %q are refused with the same reason, so at most one of them is refused by the check it is aimed at:\n  %s",
				other, tc.name, reasons[i])
		}
		seen[reasons[i]] = tc.name
	}
	// Three of the five trip three different rules, and each rule's wording is
	// its own. One distinct reason for three distinct checks is the failure this
	// whole package is measuring.
	if len(seen) < 3 {
		t.Errorf("only %d distinct refusal reasons across %d examples: the demonstrations are not distinguishable", len(seen), len(demonstrations))
	}
}

// TestTheFeaturePluginIsRefusedAReservedNameEvenHoldingTheCapability is the
// second half of the reserved-name rule, and the half a simpler implementation
// forgets.
//
// Claimable requires a KindSystem *and* the matching capability. Both halves
// are load-bearing and either one alone is wrong: a check that tested only the
// capability would pass the first demonstration — a system without
// CapCharacterSheet, refused correctly — and would then *admit* this one, since
// this plugin holds CapMaps, which is exactly the capability the "map" segment
// is reserved for. A check that tested only the kind would fail the mirror
// image, admitting the first. So the test refuses both, and then shows each
// refusal was caused by the half it names: correcting only the kind admits this
// one, and correcting only the grant admits the first.
func TestTheFeaturePluginIsRefusedAReservedNameEvenHoldingTheCapability(t *testing.T) {
	t.Parallel()

	feature := ReservedRouteAsFeature()
	granted := grantedFor(t, feature)
	if !granted.Has(plugin.CapMaps) {
		t.Fatalf("this example only proves the kind half if it actually holds the capability the segment is reserved for; granted %v",
			granted.List())
	}

	err := plugin.CheckReservedRoute(reservedRoute, plugin.KindFeature, granted)
	if err == nil {
		t.Fatalf("a feature holding %s may claim the %q segment: the kind half of the rule is not being enforced",
			plugin.CapMaps, reservedRoute)
	}
	if !strings.Contains(err.Error(), "plugin "+string(plugin.KindFeature)) {
		t.Errorf("the refusal does not name the refused plugin as a %s, so it does not say which half of the rule fired:\n  %v",
			plugin.KindFeature, err)
	}
	if accepted := plugin.CheckReservedRoute(reservedRoute, plugin.KindSystem, granted); accepted != nil {
		t.Errorf("the same grant is refused for a system, so the capability was not sufficient and this example is not isolated to the kind half: %v",
			accepted)
	}

	// And the mirror image: the first example is refused for the *other* half,
	// with a grant no capability-only check would refuse.
	system := ReservedPageTypeWithoutCapability()
	sysGranted := grantedFor(t, system)
	if sysGranted.Has(plugin.CapCharacterSheet) {
		t.Fatalf("this example only proves the capability half if it lacks the capability; granted %v", sysGranted.List())
	}
	if err := plugin.CheckReservedPageType(reservedPageType, plugin.KindSystem, sysGranted); err == nil {
		t.Errorf("a system without %s may claim %q: the capability half of the rule is not being enforced",
			plugin.CapCharacterSheet, reservedPageType)
	}
	if accepted := plugin.CheckReservedPageType(reservedPageType, plugin.KindSystem,
		sysGranted.With(plugin.CapCharacterSheet)); accepted != nil {
		t.Errorf("the grant alone is not sufficient either, so this example is not isolated to the capability half: %v", accepted)
	}
}

// TestEachExampleIsRefusedWithItsOwnReasonInTheReport is the same claim against
// the real host: the reason the boot report records is the reason the rule
// produces, not a paraphrase and not a generic denial.
//
// The wording is checked rather than the verdict, and for the same reason as
// below: a boot report whose every refusal says "invalid plugin" tells an
// administrator nothing they can act on, and a refusal is only worth anything if
// the author can tell which of their declarations to change.
func TestEachExampleIsRefusedWithItsOwnReasonInTheReport(t *testing.T) {
	t.Parallel()

	for _, tc := range demonstrations {
		if !tc.alone {
			// A collision needs two parties; see
			// TestACollidingPageTypeDisablesOnlyThatPlugin.
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := tc.construct()
			_, rep := loadRegistry(t, p)
			e := onlyEntry(t, rep, p.Descriptor().ID)
			if e.Status != plugin.StatusSkipped {
				t.Fatalf("status = %q (reason %q), want %q: a host that admits this plugin has not demonstrated the boundary at all",
					e.Status, e.Reason, plugin.StatusSkipped)
			}
			for _, want := range tc.reportNames {
				if !strings.Contains(e.Reason, want) {
					t.Errorf("the report does not say %q:\n  %s", want, e.Reason)
				}
			}
			// Where an exported rule produced the refusal, the report's line is
			// that rule's own words rather than a restatement of them: there is
			// no second wording anywhere in the path, so a rule whose message
			// changes changes the report with it and nothing can drift between
			// the two.
			if tc.quotesRule == "" {
				return
			}
			quoted := 0
			for _, c := range tc.claims {
				if c.subject != tc.quotesRule {
					continue
				}
				quoted++
				want := c.check(p.Descriptor().Kind, grantedFor(t, p))
				if want == nil {
					t.Fatalf("the rule admits %q, so there is no reason for the report to be holding", c.subject)
				}
				if !strings.Contains(e.Reason, want.Error()) {
					t.Errorf("the report does not quote the rule that refused this plugin:\n  report: %s\n  rule:   %v", e.Reason, want)
				}
			}
			if quoted != 1 {
				t.Errorf("%d claims match quotesRule %q, want 1: the loop above compared nothing", quoted, tc.quotesRule)
			}
		})
	}
}

// TestARefusedExampleContributesNothing is the half of containment that needs no
// registry.
//
// Before asking whether a host rolls back a refused plugin's contributions,
// assert that this plugin has nowhere else to put them. A plugin owning package
// state could leave something behind even with a perfect rollback, and it is this
// demo's own job to be clean: a demonstration that contaminated its package
// would make every other test here order-dependent, and a demonstration that
// contaminates the host is the thing being demonstrated against.
func TestARefusedExampleContributesNothing(t *testing.T) {
	t.Parallel()

	dir := packageDir(t)
	files := sourceFiles(t, dir)
	if len(files) == 0 {
		t.Fatal("no source files: nothing to hold to the no-package-state rule")
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		// A full parse, because ImportsOnly would leave Decls empty and the
		// shape of that is a test that passes because it looked at nothing.
		parsed := parseFileFully(t, f)
		checked += len(parsed.Decls)
		for _, decl := range parsed.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == "init" {
					t.Errorf("%s declares init(): package initialisation is a side effect that survives a refusal",
						filepath.Base(f))
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range vs.Names {
						// A blank name is a compile-time assertion that some type
						// implements some interface. It holds no state, and
						// refusing it would mean giving up the interface
						// assertions in plugin.go.
						if name.Name == "_" {
							continue
						}
						t.Errorf("%s declares package-level %s: a refused plugin must own no state of its own to leave behind",
							filepath.Base(f), name.Name)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no declarations were read: the scan above looked at nothing, so it would pass against an empty file")
	}

	// The runtime half: each example hands the host exactly what it declared, so
	// a host that refused it was holding the real thing, and two examples built
	// at different moments share nothing.
	for _, tc := range demonstrations {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := tc.construct()
			ex, ok := p.(*example)
			if !ok {
				t.Fatalf("constructor returned %T, not *example", p)
			}
			h := newFakeHost(p, grantedFor(t, p))
			if err := p.Register(context.Background(), h); err != nil {
				t.Fatalf("the example refuses itself: %v. Every demonstration here would pass against a host that checks nothing at all, because the plugin would be doing the refusing",
					err)
			}
			if h.logged == 0 {
				t.Error("Register said nothing: a plugin the host refuses is the one most in need of a log line")
			}
			if !p.Now().Equal(h.clock()) {
				t.Errorf("Now() = %v, want the host clock %v", p.Now(), h.clock())
			}
			if got := p.(plugin.PluginUI).Panels(); !reflect.DeepEqual(got, ex.panels) {
				t.Errorf("the host was offered panels %v, the plugin declared %v", got, ex.panels)
			}
			if got := p.(plugin.PluginCore).CoreTypes(); !reflect.DeepEqual(got, ex.d.PageTypes) {
				t.Errorf("the host was offered page types %v, the plugin declared %v", got, ex.d.PageTypes)
			}
			if got := plugin.RoutePatterns(h.mux); !reflect.DeepEqual(got, ex.routes) {
				t.Errorf("the host was offered routes %v, the plugin declared %v", got, ex.routes)
			}

			fresh := tc.construct().(*example)
			if fresh.host != nil {
				t.Error("registering one example gave a freshly built example a host: the constructors share state")
			}
		})
	}
}

// TestARefusedExampleContributesNothingInTheReport is the containment claim.
//
// Not "is marked skipped": *nothing is registered*. A registry that records a
// disabled plugin but keeps the page types it contributed is a registry that
// renders a page type no live plugin implements, and the rollback is the entire
// reason a refusal is safe rather than merely tidy.
func TestARefusedExampleContributesNothingInTheReport(t *testing.T) {
	t.Parallel()

	for _, tc := range demonstrations {
		if !tc.alone {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := tc.construct()
			reg, rep := loadRegistry(t, p)
			d := p.Descriptor()

			for _, pt := range d.PageTypes {
				if got, ok := reg.PageType(pt.ID); ok {
					t.Errorf("page type %q survived the refusal: %+v", pt.ID, got)
				}
			}
			if n := len(reg.PageTypes()); n != 0 {
				t.Errorf("the registry holds %d page types after refusing the only plugin that declared any", n)
			}
			if n := len(reg.Panels()); n != 0 {
				t.Errorf("the registry holds %d panels after the only contributing plugin was refused", n)
			}
			if n := len(reg.NavItems()); n != 0 {
				t.Errorf("the registry holds %d nav items after the only contributing plugin was refused", n)
			}
			if n := len(reg.Routes()); n != 0 {
				t.Errorf("the registry holds %d routes after the only contributing plugin was refused", n)
			}
			if n := len(reg.Extenders()); n != 0 {
				t.Errorf("the registry holds %d markdown extenders after the only contributing plugin was refused", n)
			}
			if n := len(reg.SearchResolvers()); n != 0 {
				t.Errorf("the registry holds %d search resolvers after the only contributing plugin was refused", n)
			}
			if n := len(reg.Summaries()); n != 0 {
				t.Errorf("the registry holds %d summary providers after the only contributing plugin was refused", n)
			}
			if _, ok := reg.Plugin(d.ID); ok {
				t.Errorf("a refused plugin is still reachable from the registry, so a request path can ask it for its config schema")
			}
			if _, ok := reg.Config(d.ID); ok {
				t.Errorf("a refused plugin still has a configuration entry, so a settings page renders a panel for a plugin that is not there")
			}

			e := onlyEntry(t, rep, d.ID)
			if e.Count.Any() {
				t.Errorf("the report counts %+v for a plugin that was refused, so the rollback did not happen: a counted contribution is one a renderer will look for", e.Count)
			}
			// HasKind is what the sidebar asks before rendering a plugin group,
			// and a group heading with nothing under it is exactly the broken
			// control §7 forbids. A refused plugin must not make it appear.
			if rep.HasKind(d.Kind) {
				t.Errorf("the report still reports a live %s after the only one was refused, so the sidebar renders a plugin group with nothing in it", d.Kind)
			}
		})
	}
}

// TestTheExampleIsVisibleRatherThanSilent is about the reason rather than the
// refusal, because that is what actually decides whether a mistake ever gets
// fixed.
//
// A plugin that fails silently fails permanently: an author sees a missing panel
// and no explanation, ships the next release on the same assumption, and the
// boundary is refuted by nothing ever having tried it. So every refusal this
// package provokes must name the claim that was refused, the kind that was
// refused, and the capability that would have been accepted — a boolean has
// none of the three.
func TestTheExampleIsVisibleRatherThanSilent(t *testing.T) {
	t.Parallel()

	refusals := 0
	for _, tc := range demonstrations {
		p := tc.construct()
		granted := grantedFor(t, p)
		for _, c := range tc.claims {
			if !c.refused {
				continue
			}
			refusals++
			err := c.check(p.Descriptor().Kind, granted)
			if err == nil {
				t.Fatalf("%s is not refused at all, so there is nothing to be visible about", c.subject)
			}
			reason := err.Error()
			if reason == "" {
				t.Fatalf("%s is refused with an empty reason: a refusal with no reason is a skipped line indistinguishable from a plugin that was never installed",
					c.subject)
			}
			if !strings.Contains(reason, c.subject) {
				t.Errorf("the refusal of %q does not say what was claimed, so the author has to guess which of their declarations to change:\n  %v",
					c.subject, err)
			}
			if !strings.Contains(reason, string(p.Descriptor().Kind)) {
				t.Errorf("the refusal of %q does not say which kind of plugin was refused:\n  %v", c.subject, err)
			}
			if !strings.Contains(reason, "capability") {
				t.Errorf("the refusal of %q does not say what would have been accepted, so it is a verdict rather than a diagnosis:\n  %v",
					c.subject, err)
			}
		}
	}
	if refusals == 0 {
		t.Fatal("no example is refused by any rule: the table has stopped demonstrating anything")
	}
}

// TestTheExampleIsVisibleRatherThanSilentInTheReport is the failure that never
// gets fixed.
//
// A plugin that fails silently fails permanently, so the claim here is not that
// the plugin was refused — that is the easy half — but that the report is a
// *line* with enough on it to act on, in an administrator's eyes, without
// leaving the page.
func TestTheExampleIsVisibleRatherThanSilentInTheReport(t *testing.T) {
	t.Parallel()

	for _, tc := range demonstrations {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := tc.construct()
			d := p.Descriptor()
			_, rep := loadRegistry(t, p)

			if len(rep.Entries) == 0 {
				t.Fatalf("the report has no entries at all: a refused plugin that is not listed is indistinguishable from one that was never installed, and the author never learns of it")
			}
			e := onlyEntry(t, rep, d.ID)
			if e.Name == "" {
				t.Error("the report line has no name: an administrator reading /admin/plugins sees an id and no idea what it was")
			}
			if e.Kind != d.Kind {
				t.Errorf("report kind = %q, want %q: a skipped system and a skipped feature are different problems with different fixes", e.Kind, d.Kind)
			}
			if e.Version != d.Version {
				t.Errorf("report version = %q, want %q", e.Version, d.Version)
			}
			if e.APILevel != d.APILevel || e.HostLevel != plugin.APILevel {
				t.Errorf("report levels = %d/%d, want %d/%d: version skew that is not visible gets shimmed forever",
					e.APILevel, e.HostLevel, d.APILevel, plugin.APILevel)
			}
			if e.Reason == "" {
				if e.Status != plugin.StatusOK && e.Status != plugin.StatusCompat {
					t.Fatalf("the report line has no reason: this is the failure this test exists to prevent")
				}
				return
			}
			// A line whose reason is present is only visible if the row is
			// findable, and Skipped() is what an administrator filters on.
			if e.Status == plugin.StatusSkipped && len(rep.Skipped()) != 1 {
				t.Errorf("the report lists %d skipped plugins, want 1: a refused plugin that is filtered out of the skipped list is invisible again", len(rep.Skipped()))
			}
		})
	}
}

// TestACollidingPageTypeDisablesOnlyThatPlugin is the collision demonstration,
// and the only one here that needs two plugins.
//
// Two claims of the same page-type id is a registry-level problem with no
// exported predicate, so it cannot be aimed at in advance the way a reservation
// can. The claim is the *containment* half: one plugin is disabled, the other
// keeps working, and the disabled one's page type is gone from the registry
// rather than ambiguously owned.
func TestACollidingPageTypeDisablesOnlyThatPlugin(t *testing.T) {
	t.Parallel()

	loser := theOtherCollision()
	reg, rep := loadRegistry(t, CollidingPlugin(), loser)

	// Both claimants have to appear, or the demonstration is a plugin vanishing
	// rather than a plugin being refused.
	entries := append(entriesFor(t, rep, ID), entriesFor(t, rep, loser.Descriptor().ID)...)
	if len(entries) != 2 {
		t.Fatalf("the report has %d lines for the two claimants, want 2: one of them is not being reported at all", len(entries))
	}
	skipped := 0
	for _, e := range entries {
		switch e.Status {
		case plugin.StatusSkipped:
			skipped++
			if !strings.Contains(e.Reason, collisionPageType) {
				t.Errorf("the refused claimant's reason does not name the colliding id %q, so the author cannot tell which of their page types collided:\n  %s",
					collisionPageType, e.Reason)
			}
		case plugin.StatusOK, plugin.StatusCompat:
		default:
			t.Errorf("unexpected status %q for %s", e.Status, e.ID)
		}
	}
	if skipped != 1 {
		t.Errorf("%d of the 2 claimants were refused, want exactly 1: a collision that disables both is a boot failure wearing a containment costume", skipped)
	}
	// The winner is chosen by the host's own sort, and the loser is the one that
	// is rolled back whole — including the panel, the nav item and the migration
	// that had nothing to do with the collision.
	loserID := loser.Descriptor().ID
	if _, ok := reg.Plugin(loserID); ok {
		t.Errorf("the refused claimant %q is still in the registry", loserID)
	}
	if pt, ok := reg.PageType(collisionPageType); !ok {
		t.Errorf("the surviving plugin's page type %q is gone from the registry: the rollback took the winner's contribution with it", collisionPageType)
	} else if pt.ID != collisionPageType {
		t.Errorf("the registry holds page type %q where %q was claimed", pt.ID, collisionPageType)
	}
	if !rep.HasKind(plugin.KindSystem) {
		t.Error("no system plugin is reported live, so the collision disabled both claimants")
	}
}

// theOtherCollision is the innocent second claimant: a different plugin
// declaring the same page-type id, with nothing else wrong with it.
//
// It exists because a collision needs two parties and every constructor in this
// package is deliberately wrong in its own way. Reusing the same type keeps the
// demonstration to the collision: TestEachExampleIsRefusedWithItsOwnReason
// already proves that neither claim can be refused by the reserved-name rule, so
// a refusal here is attributable to the collision and to nothing else.
func theOtherCollision() plugin.Plugin {
	e := CollidingPlugin().(*example)
	d := e.d
	d.ID = "example-other"
	d.Name = "Example (the other claimant)"
	return &example{d: d, routes: e.routes, panels: e.panels}
}

// TestThisPackageCompilesWithinTheBoundary is this package checking the
// boundary on itself, first.
//
// It is redundant with TestPluginImportsAreWithinBoundary, and it is here
// anyway. The whole claim of this package is that the import boundary holds for
// a plugin, and a claim tested only by the thing it is meant to prove is worth
// very little; the check nearest the code is the one most likely to notice the
// code changing. It is also the reason the violations in this package are
// declarations and registrations rather than imports: a package that would not
// compile is not evidence, because the tests asserting the refusal would never
// run.
//
// The imports are read with go/parser over this package's own files rather than
// with `go list`. `go list` shells out to the module loader, needs a working
// toolchain and a warm build cache, and answers for the whole module rather than
// for the files in this directory — while what needs asserting is a property of
// exactly these files. Reading them is cheaper, has no external dependency, and
// fails on the offending line rather than on a diff.
func TestThisPackageCompilesWithinTheBoundary(t *testing.T) {
	t.Parallel()

	dir := packageDir(t)
	files := sourceFiles(t, dir)
	if len(files) == 0 {
		t.Fatal("no source files: the boundary check has nothing to check")
	}
	for _, f := range files {
		isTest := strings.HasSuffix(f, "_test.go")
		for _, imp := range fileImports(t, f) {
			switch {
			case strings.HasPrefix(imp, internalPrefix):
				if !wantImports[imp] {
					t.Errorf("%s imports %s, which is outside the plugin boundary", filepath.Base(f), imp)
				}
			case isThirdParty(imp):
				if !wantImports[imp] {
					t.Errorf("%s imports %s, which is not on this package's allow-list", filepath.Base(f), imp)
				}
			case isTest:
			case bannedInPlugins[imp] != "":
				t.Errorf("%s imports %q: %s", filepath.Base(f), imp, bannedInPlugins[imp])
			}
		}
		if !isTest {
			assertNoClientCapability(t, f)
		}
	}
}

// internalPrefix is the module's own import prefix, so an import of ours can be
// told from a third-party one without listing either.
const internalPrefix = "github.com/PopinjayJohn/vtt-semiplane/internal/"

// wantImports is every import this package is allowed to make: one internal
// package and one external.
//
// It is an exact set rather than a restatement of the architecture test's
// allow-list, on the argument internal/plugin itself makes about Claimable — a
// second copy of a policy inside the thing being policed is how a rule and its
// enforcement drift apart. Adding an import here is the deliberate, visible act
// this table exists to force.
var wantImports = map[string]bool{
	internalPrefix + "plugin":  true,
	"github.com/go-chi/chi/v5": true,
}

// bannedInPlugins are the imports AGENTS.md §7 forbids a plugin, each with the
// reason, so a failure says which rule broke instead of printing a set diff.
//
// net/http is deliberately absent, and the reason is worth stating: a plugin
// that registers routes has to be able to name http.HandlerFunc, and what §11
// forbids is a socket, not an import. The judgement that a handler signature is
// not a client capability is the kind of judgement that stops being true the
// moment somebody adds a client to the same file — so it is asserted below
// rather than assumed.
var bannedInPlugins = map[string]string{
	"os":      "a plugin writes through the host and never directly",
	"net":     "a plugin opens no sockets",
	"os/exec": "only internal/app may run a process",
}

// clientPackages are the receivers whose methods leave the machine, and
// clientSelectors are the methods that do it. Split from clientSymbols so a
// qualified identifier can be matched as a name rather than as text.
var clientPackages = map[string]bool{"http": true, "net": true}

var clientSelectors = map[string]bool{
	"Get": true, "Head": true, "Post": true, "PostForm": true,
	"NewRequest": true, "NewRequestWithContext": true,
	"DefaultClient": true, "Client": true, "Transport": true,
	"Dial": true, "DialTimeout": true,
}

// clientSymbols are the capabilities that can leave the machine, as they appear
// in a string literal. TestNoOutboundNetwork already holds the whole tree to a
// superset of these; the copy here exists so that net/http in a plugin is a
// checked allowance rather than a gap, and so a string handed to something else
// is caught where a selector would not be.
var clientSymbols = []string{
	"http.Get(", "http.Head(", "http.Post(", "http.PostForm(",
	"http.NewRequest(", "http.NewRequestWithContext(",
	"http.DefaultClient", "http.Client{", "http.Transport{",
	"net.Dial(", "net.DialTimeout(",
}

// assertNoClientCapability holds a shipped file in this package to the
// capability half of the "no network" rule, so that the net/http exception in
// bannedInPlugins stays an exception rather than becoming a precedent.
//
// It runs over the syntax tree rather than over the file's bytes, and every
// cheaper version of this check was tried and was wrong. A byte grep failed on
// this package's own doc.go, which *names* http.DefaultClient in prose while
// explaining why the file is not allowed to use one, and a comment cannot open a
// socket. A token-stream grep was worse: a qualified identifier is several
// tokens, so joining them to find `http.DefaultClient` either breaks the name it
// is looking for or invents one across the boundary (`xhttp.Get` contains
// `http.Get`). Matching the selector itself is the only version that is right —
// a receiver named `http` or `net` with a client method on it, or a string
// literal carrying the capability for something else to use.
func assertNoClientCapability(t *testing.T, path string) {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	ast.Inspect(parsed, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			recv, ok := v.X.(*ast.Ident)
			if !ok || !clientPackages[recv.Name] || !clientSelectors[v.Sel.Name] {
				return true
			}
			t.Errorf("%s:%d: %s.%s is an outbound network capability: a plugin may name a handler and never a client, which is what the import boundary is for",
				filepath.Base(path), fset.Position(v.Pos()).Line, recv.Name, v.Sel.Name)
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return true
			}
			for _, sym := range clientSymbols {
				if strings.Contains(v.Value, sym) {
					t.Errorf("%s:%d: a string literal carries %s, which is a client capability in everything but name",
						filepath.Base(path), fset.Position(v.Pos()).Line, sym)
				}
			}
		}
		return true
	})
}

// grantedFor is the capability set the host hands a plugin.
//
// For an in-tree plugin the grant is the declaration, and that is the only
// reading under which the reserved-name rule can fire at all: PluginDeps
// carries no function that could narrow a grant, so a host handing every
// plugin All() would leave no plugin ever lacking a capability and would make
// Claimable true for every system. A reason that never fires is not a reason,
// and a test that read "granted" as All() would be testing a host that does not
// exist. lifecycle.go's Load agrees: it parses the declaration and hands that to
// the host.
func grantedFor(t *testing.T, p plugin.Plugin) plugin.Capabilities {
	t.Helper()
	d := p.Descriptor()
	granted, err := plugin.ParseCapabilities(d.Capabilities)
	if err != nil {
		t.Fatalf("%s declares a capability the host does not know: %v", d.ID, err)
	}
	return granted
}

// loadRegistry boots the host over the offered plugins with the minimum a boot
// needs: a frozen clock, no logging, no configuration, no vault, a migration
// runner that succeeds so the rollback test has something to roll back, and a
// sub-router per plugin so routes have somewhere to go.
//
// There is no error to handle, and that is the lifecycle's second decision
// rather than an accident: boot never fails because of a plugin. A campaign that
// boots with the dice system missing is a worse campaign than one that does not
// boot, so every refusal arrives as a report line and this function has nothing
// to fail on.
func loadRegistry(t *testing.T, ps ...plugin.Plugin) (plugin.Registry, plugin.Report) {
	t.Helper()
	deps := plugin.PluginDeps{
		Now:    frozenClock,
		Log:    func(context.Context, plugin.Level, string, ...plugin.KV) {},
		Config: func(string) (plugin.Config, error) { return plugin.Config{}, nil },
		FS:     func() fs.FS { return nil },
		Migrations: func(context.Context, string, []plugin.Migration) error {
			return nil
		},
		SubRouter: func(string) plugin.RouteMounter { return chi.NewRouter() },
	}
	return plugin.Load(context.Background(), deps, ps...)
}

// onlyEntry is the single report line for one plugin, with the shape of failure
// this package is about stated by the message.
func onlyEntry(t *testing.T, rep plugin.Report, id string) plugin.Entry {
	t.Helper()
	got := entriesFor(t, rep, id)
	if len(got) != 1 {
		t.Fatalf("the report has %d lines for %q, want exactly 1: a refused plugin must be reported once, visibly", len(got), id)
	}
	return got[0]
}

func entriesFor(t *testing.T, rep plugin.Report, id string) []plugin.Entry {
	t.Helper()
	var out []plugin.Entry
	for _, e := range rep.Entries {
		if e.ID == id {
			out = append(out, e)
		}
	}
	return out
}

// fakeHost is a Host that records what it is handed and implements none of it.
//
// It exists so a test can see exactly what a plugin offers the host. The whole
// demonstration rests on the host being *given* the contributions and then
// refusing them, and a plugin that quietly declined to offer them would pass
// every refusal test while proving nothing at all.
type fakeHost struct {
	kind    plugin.Kind
	granted plugin.Capabilities
	at      time.Time
	// owner is the plugin this host was built for. A real host holds it too, and
	// needs it: the patterns a plugin mounts are mounted by the host calling
	// PluginUI.RegisterRoutes on the router the host made.
	owner plugin.Plugin
	// mux is that router. Reading it back is the only way to see what a plugin
	// actually registered, which is the only thing a check can be made against.
	mux    plugin.RouteMounter
	logged int
}

func newFakeHost(owner plugin.Plugin, granted plugin.Capabilities) *fakeHost {
	return &fakeHost{
		kind:    owner.Descriptor().Kind,
		granted: granted,
		at:      frozenClock(),
		owner:   owner,
		mux:     chi.NewRouter(),
	}
}

func (h *fakeHost) Log(_ context.Context, _ plugin.Level, _ string, _ ...plugin.KV) { h.logged++ }

func (h *fakeHost) Capability() plugin.Capabilities { return h.granted }

func (h *fakeHost) Kind() plugin.Kind { return h.kind }

func (h *fakeHost) Config() plugin.Config { return plugin.Config{ID: ID} }

// FS returns nil. This plugin never asks for it, and a host that handed out a
// real vault view would be a claim several sizes larger than this package makes —
// the file being canonical, a demo has no business reading it.
func (h *fakeHost) FS() fs.FS { return nil }

// RegisterRoutes audits whatever the plugin mounted, which is the only way to
// see the patterns: a plugin that says one thing and registers another has
// registered the other, and the host checks what it can enumerate.
//
// Passed nil, it does what the real host does — nothing of the plugin's own
// router is acceptable, so the patterns are mounted on the host's router through
// PluginUI and audited afterwards.
func (h *fakeHost) RegisterRoutes(sub plugin.RouteMounter) {
	if sub != nil && sub != h.mux {
		return
	}
	if ui, ok := h.owner.(plugin.PluginUI); ok {
		ui.RegisterRoutes(h.mux)
	}
}

// RegisterPanels, RegisterPageTypes and RegisterMarkdown return nothing. Host
// offers no way to *offer* any of the three — a host calling its own getters
// gets its own view — so a plugin's contributions reach the host through
// PluginUI and PluginCore instead. That inconsistency is W1's to resolve and is
// reported rather than worked around here.
func (h *fakeHost) RegisterPanels() []plugin.Panel { return nil }

func (h *fakeHost) RegisterPageTypes() []plugin.PageType { return nil }

func (h *fakeHost) RegisterMarkdown() []any { return nil }

func (h *fakeHost) clock() time.Time { return h.at }

func (h *fakeHost) Now() time.Time { return h.at }

// frozenClock is a fixed instant rather than a package-level time.Time: a var
// holding a time is mutable state, and this package's own test asserts it owns
// none.
func frozenClock() time.Time {
	return time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
}

// packageDir is this package's own directory, named by the compiler rather than
// searched for: a test that looked for its source would find the wrong one the
// first time it ran from somewhere else.
func packageDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller did not name this file: the boundary check cannot find the package it is checking")
	}
	return filepath.Dir(file)
}

// sourceFiles is every .go file in a directory, sorted.
func sourceFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out
}

// fileImports is one file's import paths, unquoted and sorted. Parsing with
// ImportsOnly stops before the bodies, so this costs a few hundred bytes per
// file however long the file is.
func fileImports(t *testing.T, path string) []string {
	t.Helper()
	parsed := parseFile(t, path)
	out := make([]string, 0, len(parsed.Imports))
	for _, spec := range parsed.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import in %s: %v", path, err)
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// parseFile reads a file's imports and nothing else.
func parseFile(t *testing.T, path string) *ast.File {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return parsed
}

// parseFileFully is a parse that reaches the declarations. ImportsOnly would be
// cheaper and would leave Decls empty, which is the shape of a test that passes
// because it looked at nothing.
func parseFileFully(t *testing.T, path string) *ast.File {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return parsed
}

// isThirdParty reports whether an import path is domain-qualified, which is the
// standard way to tell a third-party module from a standard library package
// without maintaining a list of the standard library.
func isThirdParty(imp string) bool {
	first, _, _ := strings.Cut(imp, "/")
	return strings.Contains(first, ".")
}
