package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestArgon2ParametersAreTheAgreedOnes parses the encoded string and asserts the
// three costs and the version.
//
// It is deliberately not a round trip. A round trip passes with m=8, t=1, p=1
// just as happily as with 65536, 3, 1, and 8 KiB is a hash a laptop guesses at
// a few hundred thousand a second. The parameters are the security property;
// the encoding is the plumbing.
func TestArgon2ParametersAreTheAgreedOnes(t *testing.T) {
	t.Parallel()
	phc, err := HashPassphrase("Correct-Horse-9")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	p, err := parsePHC(phc)
	if err != nil {
		t.Fatalf("parse %q: %v", phc, err)
	}
	if p.memoryKiB != 65536 {
		t.Errorf("m = %d KiB, want 65536 (64 MiB)", p.memoryKiB)
	}
	if p.time != 3 {
		t.Errorf("t = %d, want 3", p.time)
	}
	if p.threads != 1 {
		t.Errorf("p = %d, want 1", p.threads)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Errorf("encoded hash does not carry the agreed parameters: %q", phc)
	}
}

// TestTheEncodedParametersAreWhatVerificationWillUse is the property that makes
// a future raise possible: a hash written with one parameter set verifies with
// the parameters inside it, not the ones the binary happens to hold. The fixture
// users in this package are hashed at 64 KiB rather than 64 MiB for exactly
// this reason, and this is the test that says so.
func TestTheEncodedParametersAreWhatVerificationWillUse(t *testing.T) {
	t.Parallel()
	weak, err := hashPassphraseWith("Correct-Horse-9", 64, 1, 1)
	if err != nil {
		t.Fatalf("weak hash: %v", err)
	}
	ok, err := Verify([]byte(weak), "Correct-Horse-9")
	if err != nil {
		t.Fatalf("verify weak: %v", err)
	}
	if !ok {
		t.Error("a hash written at 64 KiB did not verify; verification is using the binary's parameters, not the encoded ones")
	}
}

func TestVerifyRejectsAWrongPassphrase(t *testing.T) {
	t.Parallel()
	phc, err := HashPassphrase("Correct-Horse-9")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	for _, tc := range []struct {
		name       string
		passphrase string
	}{
		{"right passphrase", "Correct-Horse-9"},
		{"right passphrase wrong case", "correct-horse-9"},
		{"right passphrase one character off", "Correct-Horse-8"},
		{"right passphrase one character longer", "Correct-Horse-90"},
		{"empty passphrase", ""},
		{"right passphrase as a prefix", "Correct-Horse-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := Verify([]byte(phc), tc.passphrase)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if want := tc.name == "right passphrase"; ok != want {
				t.Errorf("Verify = %v, want %v", ok, want)
			}
		})
	}
}

// TestVerifyIsTimingSafeEnoughToNotBeAnOracle asserts that a login for an
// account that does not exist, a login for an account whose stored hash is of
// some other passphrase, and a login with the wrong passphrase all cost the
// same and all return the same value.
//
// The three accounts are hashed at the *production* costs, because a cheap hash
// would make one branch fast for a reason that has nothing to do with the code
// under test. The bound is loose on purpose: this is a tripwire against a
// missing burn, not a measurement of argon2, and a test that asserted a tight
// ratio would be a test that failed on a machine with a noisy neighbour.
func TestVerifyIsTimingSafeEnoughToNotBeAnOracle(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	const passphrase = "Correct-Horse-9"

	// Two real accounts, both at the production costs.
	names := []string{"oracle-a", "oracle-b"}
	for _, username := range names {
		phc, err := HashPassphrase(passphrase)
		if err != nil {
			t.Fatalf("hash for %s: %v", username, err)
		}
		salt, err := SaltFromPHC(phc)
		if err != nil {
			t.Fatalf("salt for %s: %v", username, err)
		}
		h.seedUserAt(username, phc, salt)
	}

	cases := []struct {
		name       string
		username   string
		passphrase string
	}{
		{"an account that does not exist", "no-such-account", passphrase},
		{"an account whose hash is of another passphrase", names[0], "Another-Passphrase-3"},
		{"an account with the wrong passphrase", names[1], "Wrong-Passphrase-4"},
	}
	durations := make(map[string]time.Duration, len(cases))
	for _, tc := range cases {
		started := time.Now()
		raw, err := h.svc.Create(ctx, LoginRequest{Username: tc.username, Passphrase: tc.passphrase})
		durations[tc.name] = time.Since(started)
		if raw != "" {
			t.Errorf("%s: a failed login returned a token", tc.name)
		}
		// The same value, not merely the same sentinel: a handler that renders
		// err.Error() must have nothing to render differently.
		if !errors.Is(err, ErrBadCredentials) {
			t.Errorf("%s: err = %v, want ErrBadCredentials", tc.name, err)
		}
		if err != ErrBadCredentials { //nolint:errorlint // the point is that it is the identical value
			t.Errorf("%s: the error value differs from ErrBadCredentials: %#v", tc.name, err)
		}
	}

	// A real account still works, so the equal timings above are not the timings
	// of a service that refuses everything.
	raw, err := h.svc.Create(ctx, LoginRequest{Username: names[0], Passphrase: passphrase})
	if err != nil {
		t.Fatalf("a correct login was refused: %v", err)
	}
	if !wellFormedToken(raw) {
		t.Fatalf("a correct login returned %q, which is not a token", raw)
	}

	shortest, longest := time.Duration(1<<62), time.Duration(0)
	for _, d := range durations {
		if d < shortest {
			shortest = d
		}
		if d > longest {
			longest = d
		}
	}
	// The floor is the assertion that matters: a branch that skipped argon2
	// entirely would be a few hundred microseconds and fail this.
	if shortest < 20*time.Millisecond {
		t.Errorf("the fastest failing login took %s; at least one branch is skipping the argon2id work", shortest)
	}
	if longest > 12*shortest {
		t.Errorf("failing logins ranged from %s to %s: the branches do not do the same work", shortest, longest)
	}
	t.Logf("failed-login cost: %s", durations)
}

// TestTheDummyVerifierIsNoAccountsVerifier is the property the dummy hash needs
// and the one it is easy to get wrong.
//
// The dummy is derived from a constant passphrase, so anybody can compute the
// key it holds — given the salt, which is in the string. The only thing standing
// between that and an authentication bypass is that the dummy is never stored
// and the salt is fresh per process. So the test does what an attacker would:
// it creates a real account whose passphrase *is* the dummy's, and requires
// that the account's stored verifier is a different value, and that a login for
// an account that does not exist still fails.
func TestTheDummyVerifierIsNoAccountsVerifier(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	dummy := dummyHash()
	if dummy == "" {
		t.Fatal("the dummy verifier could not be derived")
	}

	// The dummy passphrase is deliberately a valid one, so that the account can
	// really be created and the question really arises.
	if err := ValidatePassphrase(dummyPassphrase); err != nil {
		t.Fatalf("the dummy passphrase %q does not pass validation, so nobody could ever sign up with it: %v",
			dummyPassphrase, err)
	}
	phc, err := HashPassphrase(dummyPassphrase)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	h.seedUserAt("impostor", phc, nil)

	if string(h.userVerifier("impostor")) == dummy {
		t.Fatal("an account stores the dummy verifier; a login for any username would then depend on the passphrase only")
	}
	if _, err := h.svc.Create(ctx, LoginRequest{Username: "no-such-person", Passphrase: dummyPassphrase}); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("a login for an account that does not exist returned %v", err)
	}
	// And the real account still works, so the two salts really are different
	// rather than both paths being broken.
	raw, err := h.svc.Create(ctx, LoginRequest{Username: "impostor", Passphrase: dummyPassphrase})
	if err != nil {
		t.Fatalf("the account with the dummy passphrase cannot log in: %v", err)
	}
	if who, err := h.svc.Session(ctx, raw); err != nil || !who.Authenticated() {
		t.Errorf("the account's own session does not work (who=%s err=%v)", who, err)
	}
}

func TestVerifyRefusesAHashItCannotUnderstand(t *testing.T) {
	t.Parallel()
	salt := "AAAAAAAAAAAAAAAAAAAAAA"
	digest := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, tc := range []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"not a PHC string", "hunter2"},
		{"wrong algorithm", "$argon2i$v=19$m=65536,t=3,p=1$" + salt + "$" + digest},
		{"bcrypt", "$2a$10$abcdefghijklmnopqrstuv"},
		{"missing a field", "$argon2id$v=19$m=65536,t=3$" + salt},
		{"unknown version", "$argon2id$v=16$m=65536,t=3,p=1$" + salt + "$" + digest},
		{"no version", "$argon2id$m=65536,t=3,p=1$" + salt + "$" + digest},
		{"missing a cost", "$argon2id$v=19$m=65536,p=1$" + salt + "$" + digest},
		{"unknown cost key", "$argon2id$v=19$m=65536,t=3,p=1,x=1$" + salt + "$" + digest},
		{"cost is not a number", "$argon2id$v=19$m=many,t=3,p=1$" + salt + "$" + digest},
		{"zero cost", "$argon2id$v=19$m=0,t=3,p=1$" + salt + "$" + digest},
		{"salt is not base64", "$argon2id$v=19$m=65536,t=3,p=1$!!!!$" + digest},
		{"digest is not base64", "$argon2id$v=19$m=65536,t=3,p=1$" + salt + "$!!!!"},
		{"empty digest", "$argon2id$v=19$m=65536,t=3,p=1$" + salt + "$"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := Verify([]byte(tc.hash), "Correct-Horse-9")
			if !errors.Is(err, ErrMalformedHash) {
				t.Fatalf("err = %v, want ErrMalformedHash", err)
			}
			if ok {
				t.Error("a hash that would not parse was accepted")
			}
		})
	}
}

// TestVerifyRefusesAHashThatWouldExhaustMemory is the reason a cost lives
// inside a PHC string: it is a request to allocate, and it arrives from a file
// somebody can edit.
func TestVerifyRefusesAHashThatWouldExhaustMemory(t *testing.T) {
	t.Parallel()
	const digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, tc := range []struct {
		name string
		cost string
	}{
		{"a terabyte", "m=1048576"},
		{"a gigabyte", "m=262144"},
		{"just over the ceiling", "m=262145"},
		{"an absurd time cost", "t=1000000"},
		{"an absurd degree of parallelism", "p=4096"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hash := "$argon2id$v=19$m=65536,t=3,p=1$"
			hash = strings.Replace(hash, "m=65536,t=3,p=1", tc.cost, 1)
			hash += "AAAAAAAAAAAAAAAAAAAAAA$" + digest
			if _, err := Verify([]byte(hash), "Correct-Horse-9"); !errors.Is(err, ErrMalformedHash) {
				t.Fatalf("err = %v, want ErrMalformedHash", err)
			}
		})
	}
}

// TestValidatePassphrase is the table the whole rule set hangs off.
func TestValidatePassphrase(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		passphrase string
		reason     string
	}{
		{"long enough and mixed", "Correct-Horse-9", ""},
		{"long enough, mixed by punctuation", "correct-horse-battery", ""},
		{"exactly the minimum", "Abcdefghij", ""},
		{"one repeated character with one change", "-----------a", ""},
		{"a passphrase with spaces", "correct horse battery staple", ""},
		{"a passphrase with a non-ASCII letter", "correct-horse-batterÿ", ""},

		{"one short of the minimum", "Abcdefghi", "must be at least 10 characters"},
		{"empty", "", "must be at least 10 characters"},

		{"one repeated character", "aaaaaaaaaaaaaa", "must not be one character repeated"},
		{"one repeated symbol", "-------------", "must not be one character repeated"},
		{"one repeated non-ASCII character", "éééééééééé", "must not be one character repeated"},

		// The one-class rule is the blunt half of this function. A long
		// all-lowercase passphrase is not weak in any useful sense, and the
		// cases below are here to pin the rule the specification asks for
		// rather than to endorse it.
		{"all lowercase", "correcthorsebattery", "must mix cases, digits or symbols"},
		{"all uppercase", "CORRECTHORSEBATTERY", "must mix cases, digits or symbols"},
		{"all digits", "1234567890123456789", "must mix cases, digits or symbols"},
		{"all symbols", "~^:;|><,[]{}!@#$%", "must mix cases, digits or symbols"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassphrase(tc.passphrase)
			switch {
			case tc.reason == "" && err != nil:
				t.Fatalf("ValidatePassphrase(%q) = %v, want nil", tc.passphrase, err)
			case tc.reason != "" && err == nil:
				t.Fatalf("ValidatePassphrase(%q) = nil, want %q", tc.passphrase, tc.reason)
			case tc.reason != "" && !errors.Is(err, ErrWeakPassphrase):
				t.Fatalf("err = %v, want it to match ErrWeakPassphrase", err)
			}
			if tc.reason != "" && !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("reason = %q, want it to mention %q", err.Error(), tc.reason)
			}
		})
	}
}

// BenchmarkVerify reports the real cost of one authentication at the agreed
// parameters, because the honest number is the only one worth knowing: this is
// the work every login request does, and it is why a login endpoint is
// rate-limited (config.RateLoginPerMinute) and why the tests above keep the
// number of real derivations small.
func BenchmarkVerify(b *testing.B) {
	phc, err := HashPassphrase("Correct-Horse-9")
	if err != nil {
		b.Fatalf("hash: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ok, err := Verify([]byte(phc), "Correct-Horse-9")
		if err != nil || !ok {
			b.Fatalf("verify: %v ok=%v", err, ok)
		}
	}
}

// BenchmarkHashPassphrase is the cost of creating an account, which is what an
// invite redemption and the first-run setup each pay once.
func BenchmarkHashPassphrase(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := HashPassphrase("Correct-Horse-9"); err != nil {
			b.Fatalf("hash: %v", err)
		}
	}
}

// BenchmarkHashPassphraseCheap is the fixture cost, for comparison.
func BenchmarkHashPassphraseCheap(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := hashPassphraseWith("Correct-Horse-9", cheapMemoryKiB, cheapPasses, cheapThreads); err != nil {
			b.Fatalf("hash: %v", err)
		}
	}
}
