package status

import (
	"crypto"
	"fmt"
	"github.com/fluidkeys/crypto/openpgp/packet"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/compression"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/hash"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/symmetric"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/policy"
	"testing"
	"time"
)

var (
	feb1st           = time.Date(2018, 2, 1, 0, 0, 0, 0, time.UTC)
	march1st         = time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC)
	march1stLeapYear = time.Date(2020, 3, 1, 0, 0, 0, 0, time.UTC)

	anotherTimezone = time.FixedZone("UTC+8", 8*60*60)
)

func TestGetEarliestExpiryTime(t *testing.T) {
	key, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
	if err != nil {
		t.Fatal(err)
	}
	hasExpiry, earliestExpiry := getEarliestExpiryTime(*key)

	if !hasExpiry {
		t.Fatalf("expected hasExpiry=true")
	}

	expected := time.Date(2038, 9, 7, 9, 5, 3, 0, time.UTC)

	if *earliestExpiry != expected {
		t.Fatalf("expected earliestExpiry=%v, got %v", expected, *earliestExpiry)
	}
}

func TestEarliest(t *testing.T) {
	times := []time.Time{feb1st, march1st}

	expected := feb1st

	got := earliest(times)
	if got != expected {
		t.Fatalf("earliest(): expected '%v', got '%v'", expected, got)
	}
}

func TestDateHelpers(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	expiryInFuture := now.Add(time.Duration(1) * time.Hour)
	expiryInPast := now.Add(time.Duration(-1) * time.Hour)

	t.Run("isExpired with past date", func(t *testing.T) {
		if isExpired(expiryInPast, now) != true {
			t.Errorf("expected isExpired(%v, %v) to return true", expiryInPast, now)
		}

	})

	t.Run("isExpired with future date", func(t *testing.T) {
		if isExpired(expiryInFuture, now) != false {
			t.Errorf("expected isExpired(%v, %v) to return true", expiryInFuture, now)
		}
	})

	t.Run("getDaysSinceExpiry 1 hour in the past", func(t *testing.T) {
		expected := uint(0)
		got := getDaysSinceExpiry(now.Add(time.Duration(-1)*time.Hour), now)

		if got != expected {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("getDaysSinceExpiry 25 hours in the past", func(t *testing.T) {
		expected := uint(1)
		got := getDaysSinceExpiry(now.Add(time.Duration(-25)*time.Hour), now)

		if got != expected {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("getDaysUntilExpiry 1 hour in the future", func(t *testing.T) {
		expected := uint(0)
		got := getDaysUntilExpiry(now.Add(time.Duration(1)*time.Hour), now)

		if got != expected {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("getDaysUntilExpiry 25 hours in the future", func(t *testing.T) {
		expected := uint(1)
		got := getDaysUntilExpiry(now.Add(time.Duration(25)*time.Hour), now)

		if got != expected {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})
}

func TestGetEncryptionSubkeyWarnings(t *testing.T) {
	t.Run("with a primary key with long expiry date and a subkey overdue for rotation", func(t *testing.T) {
		pgpKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey2, "test2")
		if err != nil {
			t.Fatalf("Failed to load example test data: %v", err)
		}

		now := time.Date(2018, 9, 24, 18, 0, 0, 0, time.UTC)
		verySoon := now.Add(time.Duration(6) * time.Hour)
		veryFarAway := now.Add(time.Duration(100*24) * time.Hour)

		err = pgpKey.UpdateSubkeyValidUntil(pgpKey.EncryptionSubkey().PublicKey.KeyId, verySoon)
		if err != nil {
			t.Fatalf("failed to update expiry on test subkey")
		}

		err = pgpKey.UpdateExpiryForAllUserIds(veryFarAway)
		if err != nil {
			t.Fatalf("failed to update expiry on test key")
		}

		t.Run("test we get subkey overdue for rotation warning", func(t *testing.T) {
			expected := []KeyWarning{
				KeyWarning{Type: SubkeyOverdueForRotation},
			}

			got := getEncryptionSubkeyWarnings(*pgpKey, now)

			assertEqualSliceOfKeyWarningTypes(t, expected, got)
		})

		t.Run("test we get primary key long expiry warning", func(t *testing.T) {
			expected := []KeyWarning{
				KeyWarning{Type: PrimaryKeyLongExpiry},
			}

			now := time.Date(2018, 9, 24, 18, 0, 0, 0, time.UTC)
			got := getPrimaryKeyWarnings(*pgpKey, now)

			assertEqualSliceOfKeyWarningTypes(t, expected, got)
		})
	})
}

func TestGetSignatureHashWarnings(t *testing.T) {
	// OpenPGP hashes:
	// https://tools.ietf.org/html/rfc4880#section-9.4
	// Golang hash declarations:
	// https://godoc.org/crypto#Hash

	hashAlgorithmsWarn := []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
	}

	hashAlgorithmsNoWarn := []crypto.Hash{
		crypto.SHA512,
		crypto.SHA384,
		crypto.SHA224,
		crypto.SHA256,
	}

	for _, algo := range hashAlgorithmsWarn {
		t.Run(fmt.Sprintf("with weak hash algorithm %v", algo), func(t *testing.T) {
			sig := packet.Signature{Hash: algo}

			t.Run("getSelfSignatureHashWarnings should return WeakSelfSignatureHash", func(t *testing.T) {
				got := getSelfSignatureHashWarnings(&sig)
				expected := []KeyWarning{
					KeyWarning{
						Type:   WeakSelfSignatureHash,
						Detail: nameOfHash(algo),
					},
				}

				assertEqualSliceOfKeyWarningTypes(t, expected, got)
			})

			t.Run("getSubkeyBindingSignatureHashWarnings should return WeakSubkeyBindingSignatureHash", func(t *testing.T) {
				got := getSubkeyBindingSignatureHashWarnings(&sig)
				expected := []KeyWarning{
					KeyWarning{
						Type:   WeakSubkeyBindingSignatureHash,
						Detail: nameOfHash(algo),
					},
				}

				assertEqualSliceOfKeyWarningTypes(t, expected, got)
			})
		})
	}

	for _, algo := range hashAlgorithmsNoWarn {
		t.Run(fmt.Sprintf("good hash algorithm %v", algo), func(t *testing.T) {
			sig := packet.Signature{Hash: algo}

			t.Run("getSelfSignatureHashWarnings should return WeakSelfSignatureHash", func(t *testing.T) {
				got := getSelfSignatureHashWarnings(&sig)
				expected := []KeyWarning{}
				assertEqualSliceOfKeyWarningTypes(t, expected, got)
			})

			t.Run("getSubkeyBindingSignatureHashWarnings should return WeakSubkeyBindingSignatureHash", func(t *testing.T) {
				got := getSubkeyBindingSignatureHashWarnings(&sig)
				expected := []KeyWarning{}
				assertEqualSliceOfKeyWarningTypes(t, expected, got)
			})
		})
	}

}

func TestGetCipherPreferenceWarnings(t *testing.T) {
	const (
		// https://tools.ietf.org/html/rfc4880#section-9.2
		idea        = symmetric.IDEA
		tripleDes   = symmetric.TripleDES
		cast5       = symmetric.CAST5
		blowfish    = symmetric.Blowfish
		aes256      = symmetric.AES256
		aes192      = symmetric.AES192
		aes128      = symmetric.AES128
		twofish     = symmetric.Twofish256
		camellia128 = symmetric.Camellia128
		camellia192 = symmetric.Camellia192
		camellia256 = symmetric.Camellia256
	)

	acceptableCipherCombinations := policy.AcceptablePreferredSymmetricAlgorithms

	for _, cipherPrefs := range acceptableCipherCombinations {
		t.Run(fmt.Sprintf("no warnings for acceptable cipher preferences %v", cipherPrefs), func(t *testing.T) {
			expected := []KeyWarning{}
			got := getCipherPreferenceWarnings(cipherPrefs)
			assertEqualSliceOfKeyWarningTypes(t, expected, got)
		})
	}

	t.Run("warn about empty cipher preferences", func(t *testing.T) {
		// > Note also that if an implementation does not implement
		// > the preference, then it is implicitly a TripleDES-only
		// > implementation.
		expected := []KeyWarning{
			KeyWarning{Type: MissingPreferredSymmetricAlgorithms},
		}
		got := getCipherPreferenceWarnings([]uint8{} /* empty */)
		assertEqualSliceOfKeyWarningTypes(t, expected, got)
	})

	unsupportedCipherPreferences := []uint8{
		// idea, blowfish, twofish and camellia are unsupported by crypto/openpgp
		idea, blowfish, twofish, camellia128, camellia192, camellia256,
	}

	for _, cipherByte := range unsupportedCipherPreferences {
		t.Run(fmt.Sprintf("warn for unsupported cipher preferences %d", cipherByte), func(t *testing.T) {
			expectedWarning := KeyWarning{
				Type:   UnsupportedPreferredSymmetricAlgorithm,
				Detail: symmetric.Name(cipherByte),
			}
			gotWarnings := getCipherPreferenceWarnings([]uint8{cipherByte})
			assertKeyWarningsContains(t, gotWarnings, expectedWarning)
		})
	}

	weakCipherPreferencesSample := [][]uint8{
		// TripleDES is implicitly supported as a fallback, don't
		// explicitly define it
		[]uint8{aes256, aes192, aes128, tripleDes},

		// don't support only aes256
		[]uint8{aes256},

		// don't support only aes128
		[]uint8{aes128},

		// don't specify smaller AES key sizes before longer ones
		[]uint8{aes192, aes256, aes128},
		[]uint8{aes128, aes192, aes256},
		[]uint8{aes256, aes128, aes192},

		// don't specify CAST5 before AES
		[]uint8{cast5, aes256, aes192, aes128},
	}

	for _, cipherPrefs := range weakCipherPreferencesSample {
		t.Run(fmt.Sprintf("warn for weak cipher preferences %v", cipherPrefs), func(t *testing.T) {
			expected := []KeyWarning{
				KeyWarning{
					Type:   WeakPreferredSymmetricAlgorithms,
					Detail: joinCipherNames(cipherPrefs),
				},
			}
			got := getCipherPreferenceWarnings(cipherPrefs)
			assertEqualSliceOfKeyWarningTypes(t, expected, got)
		})
	}
}

func TestGetHashPreferenceWarnings(t *testing.T) {
	const (
		// https://tools.ietf.org/html/rfc4880#section-9.4
		sha512    = uint8(hash.Sha512)
		sha384    = hash.Sha384
		sha256    = hash.Sha256
		sha224    = hash.Sha224
		ripemd160 = hash.Ripemd160
		sha1      = hash.Sha1
		md5       = hash.Md5
	)

	acceptableHashCombinations := policy.AcceptablePreferredHashAlgorithms

	for _, hashPrefs := range acceptableHashCombinations {
		t.Run(fmt.Sprintf("no warnings for acceptable hash preferences %v", hashPrefs), func(t *testing.T) {
			expected := []KeyWarning{}
			got := getHashPreferenceWarnings(hashPrefs)
			assertEqualSliceOfKeyWarningTypes(t, expected, got)
		})
	}

	t.Run("warn about empty hash preferences", func(t *testing.T) {
		expected := []KeyWarning{
			KeyWarning{Type: MissingPreferredHashAlgorithms},
		}
		got := getHashPreferenceWarnings([]uint8{})
		assertEqualSliceOfKeyWarningTypes(t, expected, got)
	})

	unsupportedHashAlgorithms := []uint8{
		4, 5, 6, 7, // "Reserved"
		100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, // "Private / experimental algorithm"
		111, 128, 255, // 111 to 255 aren't specified so shouldn't be used
	}

	for _, hashByte := range unsupportedHashAlgorithms {
		t.Run(fmt.Sprintf("warn for unsupported hash preference %d", hashByte), func(t *testing.T) {
			expectedWarning := KeyWarning{
				Type:   UnsupportedPreferredHashAlgorithm,
				Detail: hash.Name(hashByte),
			}
			gotWarnings := getHashPreferenceWarnings([]uint8{hashByte})
			assertKeyWarningsContains(t, gotWarnings, expectedWarning)
		})
	}

	weakHashPreferencesSample := [][]uint8{
		// SHA1 and MD5 algos should never be specified anywhere in
		// preferences.
		// > MD5 is deprecated.
		// > Implementations MUST implement SHA-1.
		// > Since SHA1 is the MUST-implement hash algorithm, if it is not
		// > explicitly in the list, it is tacitly at the end.
		//
		// Given that SHA1 is *implicitly* supported, don't advertise
		// support for it. Possibly it will be deprecated in future
		// versions.

		// The aim is preferences is to support the *largest number* of
		// *strong* algorithms, so that your intersection with another user
		// is large and safe.

		[]uint8{md5},
		[]uint8{sha512, sha384, sha256, sha224, md5},

		[]uint8{sha1},
		[]uint8{sha512, sha384, sha256, sha224, sha1},

		// bad: ripemd160 only acceptable after the whole sha2 family
		[]uint8{sha512, sha384, sha256, ripemd160, sha224},
		[]uint8{sha512, sha384, ripemd160, sha256, sha224},
		[]uint8{sha512, ripemd160, sha384, sha256, sha224},
		[]uint8{ripemd160, sha512, ripemd160, sha384, sha256, sha224},

		// bad: all sha-2 should be supported
		[]uint8{sha512}, // implementations that only support sha256 would fall back to sha1
		[]uint8{sha256},
		[]uint8{sha384, sha256, sha224}, // missing sha512
		[]uint8{sha512, sha256, sha224}, // missing sha384
		[]uint8{sha512, sha384, sha224}, // missing sha256
		[]uint8{sha512, sha384, sha256}, // missing sha224

		// bad: sha-2 family not in descending size order
		[]uint8{sha384, sha512, sha256, sha224},
		[]uint8{sha256, sha512, sha384, sha224},
	}

	for _, hashPrefs := range weakHashPreferencesSample {
		t.Run(fmt.Sprintf("warn for weak hash preferences %v", hashPrefs), func(t *testing.T) {
			expected := []KeyWarning{
				KeyWarning{
					Type:   WeakPreferredHashAlgorithms,
					Detail: joinHashNames(hashPrefs),
				},
			}
			got := getHashPreferenceWarnings(hashPrefs)
			assertEqualSliceOfKeyWarningTypes(t, expected, got)
		})
	}

}

func TestGetCompressionPreferenceWarnings(t *testing.T) {
	t.Run("empty compression preferences", func(t *testing.T) {
		expected := []KeyWarning{
			KeyWarning{Type: MissingPreferredCompressionAlgorithms},
		}
		got := getCompressionPreferenceWarnings([]uint8{})
		assertEqualSliceOfKeyWarningTypes(t, expected, got)
	})

	t.Run("warn if doesn't support uncompressed", func(t *testing.T) {
		prefsWithoutUncompressed := []uint8{uint8(compression.ZIP)}

		expected := []KeyWarning{
			KeyWarning{Type: MissingUncompressedPreference},
		}
		got := getCompressionPreferenceWarnings(prefsWithoutUncompressed)
		assertEqualSliceOfKeyWarningTypes(t, expected, got)
	})

	t.Run("warn about unsupported BZIP", func(t *testing.T) {
		prefsWithBzip := []uint8{
			compression.ZIP,
			compression.Uncompressed,
			compression.BZIP2,
		}

		expected := []KeyWarning{
			KeyWarning{
				Type:   UnsupportedPreferredCompressionAlgorithm,
				Detail: "BZIP2",
			},
		}
		got := getCompressionPreferenceWarnings(prefsWithBzip)
		assertEqualSliceOfKeyWarningTypes(t, expected, got)
	})
}

func assertKeyWarningsContains(t *testing.T, gotWarnings []KeyWarning, expectedWarning KeyWarning) {
	t.Helper()

	got := false

	for _, gotWarning := range gotWarnings {
		if gotWarning == expectedWarning {
			got = true
		}
	}

	if !got {
		t.Fatalf("didn't find expected KeyWarning %v in %v", expectedWarning, gotWarnings)
	}
}

// assertEqualSliceOfKeyWarnings compares two slices of keywarnings and calls
// t.Fatalf with a message if they differ.
func assertEqualSliceOfKeyWarningTypes(t *testing.T, expected, got []KeyWarning) {
	t.Helper()
	if len(expected) != len(got) {
		t.Fatalf("expected length %d, got %d. expected: %v, got: %v",
			len(expected), len(got), expected, got)
	}
	for i := range expected {
		if expected[i].Type != got[i].Type {
			t.Fatalf("expected[%d].Type differs, expected '%d', got '%d'", i, expected[i].Type, got[i].Type)
		}
	}

}
