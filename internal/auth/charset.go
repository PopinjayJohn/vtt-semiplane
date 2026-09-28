package auth

// The character classes both validators measure over, shared so that a
// passphrase and a username agree on what a letter is. Four value classes plus
// the username punctuation, not two: ten digits in a row are no better than ten
// letters in a row, and a rule that counted only cases would wave them through.
const (
	classLower uint8 = 1 << iota
	classUpper
	classDigit
	classSymbol
	classPunct
)

// classOf returns the bit for a rune's class. Everything outside ASCII is
// classSymbol, which is what keeps a username inside the ASCII-only rule the
// COLLATE NOCASE unique index depends on.
func classOf(r rune) uint8 {
	switch {
	case r >= 'a' && r <= 'z':
		return classLower
	case r >= 'A' && r <= 'Z':
		return classUpper
	case r >= '0' && r <= '9':
		return classDigit
	case r == '-' || r == '.' || r == '_':
		return classPunct
	default:
		return classSymbol
	}
}
