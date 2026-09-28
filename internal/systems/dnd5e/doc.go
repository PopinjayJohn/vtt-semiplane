// Package dnd5e is the reference system plugin: the character and rule page
// types, a sheet editor, one right-sidebar panel, and a search resolver.
//
// It exists so that the plugin architecture is proven against real code rather
// than against its own documentation. A change to core that only this plugin
// needs is a bug in the architecture, and the two reserved page-type ids it
// claims — character and rule — are among the few names in the system whose
// reservation is exercised by something that ships.
//
// The files are split by what they own. plugin.go is the Plugin implementation
// and the static declaration behind it: capabilities, page types, navigation,
// configuration, migration, and the search resolver. hostcall.go is the two
// halves the host calls into — PluginCore and PluginUI — and the HTTP handlers
// behind them. The .templ files are components over Go values this package owns.
// None of them is handed vault content this package cannot already reach, and
// none of them contains a script, a style or a DOM handle, because the Host
// interface has no method that could install one.
package dnd5e
