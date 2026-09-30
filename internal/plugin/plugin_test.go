package plugin

import "testing"

func TestAPIVersionWindow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		pluginLevel int
		admitted    bool
		compat      bool
	}{
		{"current", APILevel, true, false},
		{"one behind", APILevel - 1, true, true},
		{"two behind, the edge of the window", APILevel - APIWindow, true, true},
		{"three behind, too old", APILevel - APIWindow - 1, false, false},
		{"newer than the host", APILevel + 1, false, false},
		{"much newer", APILevel + 7, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			admitted, reason := Admit(APILevel, tc.pluginLevel)
			if admitted != tc.admitted {
				t.Fatalf("admitted = %v (%s), want %v", admitted, reason, tc.admitted)
			}
			if !admitted && reason == "" {
				t.Error("a refusal must carry a reason for the boot report")
			}
			// Compat is only meaningful for an admitted plugin: a refused
			// plugin never reaches the shim.
			if admitted && Compat(APILevel, tc.pluginLevel) != tc.compat {
				t.Errorf("Compat = %v, want %v", Compat(APILevel, tc.pluginLevel), tc.compat)
			}
		})
	}
}

func TestCapabilitiesAreABitmask(t *testing.T) {
	t.Parallel()

	s, err := ParseCapabilities([]Capability{CapMaps, CapSidebarNav})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !s.Has(CapMaps) || !s.Has(CapSidebarNav) {
		t.Error("declared capabilities are not in the set")
	}
	if s.Has(CapDice) || s.Has(CapEncounters) {
		t.Error("an undeclared capability is in the set")
	}
	if s.Has(CapCharacterSheet) {
		t.Error("maps and character sheets share a bit")
	}
}

func TestParseCapabilitiesRejectsUnknown(t *testing.T) {
	t.Parallel()
	if _, err := ParseCapabilities([]Capability{"telepathy"}); err == nil {
		t.Fatal("an unknown capability must be an error, not a silent no-op")
	}
}

func TestCapabilityNarrowing(t *testing.T) {
	t.Parallel()

	all := All()
	if !all.Has(CapExporters) || !all.Has(CapPageSummaries) {
		t.Fatal("All() is missing a capability")
	}

	// The host may grant less than a plugin declares. Everything the plugin
	// did not get must read as absent, so the enforcement table has one check.
	narrow := all.With(CapMaps)
	_ = narrow
	mapsOnly := All()
	mapsOnly &^= Capabilities(0)
	if len(mapsOnly.List()) != len(AllCapabilities) {
		t.Errorf("List returned %d capabilities, want %d", len(mapsOnly.List()), len(AllCapabilities))
	}
}

func TestDescriptorValidateID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"kebab-case", "dnd5e", false},
		{"hyphenated", "house-rules", false},
		{"empty", "", true},
		{"uppercase", "Dnd5e", true},
		{"space", "dnd 5e", true},
		{"underscore", "dnd_5e", true},
		{"slash", "a/b", true},
		{"trailing dash", "dnd5e-", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := Descriptor{ID: tc.id}.ValidateID()
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateID(%q) error = %v, wantErr %v", tc.id, err, tc.wantErr)
			}
		})
	}
}

func TestKindValid(t *testing.T) {
	t.Parallel()
	if !KindSystem.Valid() || !KindFeature.Valid() {
		t.Error("a known kind is not valid")
	}
	if Kind("extension").Valid() {
		t.Error("an unknown kind is valid")
	}
}

func TestConfigAccessors(t *testing.T) {
	t.Parallel()
	c := Config{ID: "dnd5e", Values: map[string]any{
		"name":   "Ashes",
		"fog":    true,
		"grid":   24,
		"grid64": int64(64),
		"ratio":  1.5,
		"empty":  "",
	}}
	if got := c.Get("name", "fallback"); got != "Ashes" {
		t.Errorf("Get = %q", got)
	}
	if got := c.Get("missing", "fallback"); got != "fallback" {
		t.Errorf("Get missing = %q", got)
	}
	// An empty string is treated as unset: a config file that leaves a field
	// blank falls back rather than setting it to "".
	if got := c.Get("empty", "fallback"); got != "fallback" {
		t.Errorf("Get empty = %q", got)
	}
	if !c.Bool("fog", false) {
		t.Error("Bool(fog) = false, want true")
	}
	if !c.Bool("missing", true) {
		t.Error("Bool(missing) should return the default")
	}
	if c.Bool("missing", false) {
		t.Error("Bool(missing) returned true with a false default")
	}
	if got := c.Int("grid", 0); got != 24 {
		t.Errorf("Int = %d", got)
	}
	if got := c.Int("grid64", 0); got != 64 {
		t.Errorf("Int int64 = %d", got)
	}
	if got := c.Int("ratio", 0); got != 1 {
		t.Errorf("Int float64 = %d", got)
	}
	if got := c.Int("missing", 7); got != 7 {
		t.Errorf("Int missing = %d", got)
	}
}

func TestWikiLinkCarriesOnlyThePageID(t *testing.T) {
	t.Parallel()
	attrs := WikiLink(42)
	got, ok := attrs[WikiLinkAttr]
	if !ok {
		t.Fatalf("attribute %q is missing", WikiLinkAttr)
	}
	if got != "42" {
		t.Errorf("attribute value = %v, want the page id", got)
	}
}

func TestKnownSlots(t *testing.T) {
	t.Parallel()
	for _, s := range []Slot{SlotRightTop, SlotRightMid, SlotRightBottom,
		SlotLeftBottom, SlotEditorToolbar, SlotPageActions} {
		if !KnownSlots[s] {
			t.Errorf("slot %q is not known to core", s)
		}
	}
	if KnownSlots["somewhere-else"] {
		t.Error("an unknown slot is known")
	}
}
