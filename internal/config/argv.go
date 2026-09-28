package config

import (
	"flag"
	"strings"
)

// reorder moves args' operands behind its flags, so that flag.Parse sees every
// flag whatever order the user wrote them in.
//
// The flag package stops at the first non-flag argument, which is what makes
// `semiplane restore --from DIR` fail: --from is never seen, Validate then
// reports "restore requires --from", and the operator's command is rejected for
// a flag they typed exactly as the help spells it. There is no mode in the
// package to change that, so the arguments are reordered before Parse rather
// than after.
//
// It is done here, inside config, for one reason: reorder has to know which
// flags take a value so it does not mistake a flag's value for the next flag,
// and the only copy of that knowledge is the FlagSet Parse is about to run. An
// argv partitioner in the executable would need a second list of flag names,
// and a flag added to config without being added to that list fails silently —
// a dropped --vault opens a different vault than the one the operator named.
// Asking the same FlagSet means a new flag is correct on both sides of a
// subcommand with nothing to update.
//
// The partition is: config's own flags first, in the order written; then the
// operands; then the flags config does not define, which belong to the
// subcommand and reach the caller as its arguments (`reindex --full`).
//
// A flag config does not define is deferred only once a subcommand has been
// read. Before that there is nothing to defer it to, so it is left where Parse
// can refuse it: `semiplane --vaultt /srv/v` is a typo, and a typo that reached
// the end of the argument list as an operand would be taken for a subcommand and
// run as one.
func reorder(fs *flag.FlagSet, args []string) []string {
	var flags, operands, subcommand []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			// flag's own terminator: nothing after it is a flag, whatever it
			// looks like, and it has to stay ahead of what follows it.
			operands = append(operands, args[i:]...)
			return concat(flags, operands, subcommand)

		case !isFlagToken(arg):
			operands = append(operands, arg)

		case !knownFlag(fs, arg) && len(operands) > 0:
			subcommand = append(subcommand, arg)

		case takesSeparateValue(fs, arg):
			// A value flag with nothing after it is left short, so Parse
			// refuses it with the message it has always written rather than
			// one invented here.
			flags = append(flags, arg)
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}

		default:
			// A boolean, a flag with an inline value, and an unknown flag that
			// no subcommand has claimed — which is the last one Parse refuses,
			// and is meant to.
			flags = append(flags, arg)
		}
	}
	return concat(flags, operands, subcommand)
}

// isFlagToken reports whether arg is something flag.Parse would try to read as
// a flag. A lone "-" is an operand to it, as it is to a shell.
func isFlagToken(arg string) bool {
	return len(arg) > 1 && strings.HasPrefix(arg, "-")
}

// flagName is arg's name in the spelling FlagSet.Lookup takes: no leading
// dashes and no inline value.
func flagName(arg string) string {
	name, _, _ := strings.Cut(arg, "=")
	return strings.TrimLeft(name, "-")
}

// knownFlag reports whether config defines this flag, in either spelling and
// with or without an inline value.
func knownFlag(fs *flag.FlagSet, arg string) bool {
	return fs.Lookup(flagName(arg)) != nil
}

// takesSeparateValue reports whether the flag's value is the next argument
// rather than something written after an "=".
//
// The question is asked of the flag's own value, exactly as flag.parseOne asks
// it, so a flag defined as a boolean here is a boolean there.
func takesSeparateValue(fs *flag.FlagSet, arg string) bool {
	if strings.Contains(arg, "=") {
		return false
	}
	f := fs.Lookup(flagName(arg))
	if f == nil {
		return false
	}
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return !ok || !bf.IsBoolFlag()
}

// concat joins the groups into one argument list.
func concat(groups ...[]string) []string {
	n := 0
	for _, g := range groups {
		n += len(g)
	}
	out := make([]string, 0, n)
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}
