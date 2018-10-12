package pgpkey

import (
	"fmt"
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/policy"
)

func TestGenerate(t *testing.T) {
	janeEmail := "jane@example.com"
	now := time.Date(2018, 6, 15, 16, 0, 0, 0, time.UTC)
	generatedKey, err := Generate(janeEmail, now, mockRandom)

	if err != nil {
		t.Errorf("failed to generate PGP key in tests")
	}

	t.Run("generate makes a UID with just an email and no brackets", func(t *testing.T) {
		armored, err := generatedKey.Armor()
		if err != nil {
			t.Errorf("failed to ascii armor key: %v", err)
		}
		entity, err := LoadFromArmoredPublicKey(armored)
		if err != nil {
			t.Errorf("failed to load example PGP key: %v", err)
		}
		expected := "<" + janeEmail + ">"
		actual := getSingleUid(entity.Identities)

		if expected != actual {
			t.Errorf("expected UID '%s', got '%s'", expected, actual)
		}
	})

	t.Run(fmt.Sprintf("PrimaryKey RSA key has %d bits", policy.PrimaryKeyRsaKeyBits), func(t *testing.T) {
		var bitLength uint16
		bitLength, err = generatedKey.PrimaryKey.BitLength()
		if err != nil {
			t.Fatalf("failed to get primary key BitLength: %v", err)
		}

		fmt.Printf("bitLength: %d\n", bitLength)
		if policy.PrimaryKeyRsaKeyBits != bitLength {
			t.Fatalf("bitlength expected %d, got %d", policy.PrimaryKeyRsaKeyBits, bitLength)
		}
	})

	t.Run("PrimaryKey.CreationTime is correct", func(t *testing.T) {
		assert.AssertEqualTimes(t, now, generatedKey.PrimaryKey.CreationTime)
	})

	for name, identity := range generatedKey.Identities {
		t.Run(fmt.Sprintf("Identity[%s].SelfSignature.CreationTime", name), func(t *testing.T) {
			assert.AssertEqualTimes(t, now, identity.SelfSignature.CreationTime)
		})

		t.Run(fmt.Sprintf("UserID[%s].SelfSignature.PreferredSymmetric matches policy", name), func(t *testing.T) {
			assert.Equal(
				t,
				policy.AdvertiseCipherPreferences,
				identity.SelfSignature.PreferredSymmetric,
			)
		})

		t.Run(fmt.Sprintf("UserID[%s].SelfSignature.PreferredHash matches policy", name), func(t *testing.T) {
			assert.Equal(
				t,
				policy.AdvertiseHashPreferences,
				identity.SelfSignature.PreferredHash,
			)
		})

		t.Run(fmt.Sprintf("UserID[%s].SelfSignature.PreferredCompression matches policy", name), func(t *testing.T) {
			assert.Equal(
				t,
				policy.AdvertiseCompressionPreferences,
				identity.SelfSignature.PreferredCompression,
			)
		})

		t.Run(fmt.Sprintf("UserID[%s].SelfSignature.Hash matches policy", name), func(t *testing.T) {
			assert.Equal(t, policy.SignatureHashFunction, identity.SelfSignature.Hash)
		})
	}

	for i, subkey := range generatedKey.Subkeys {
		t.Run(fmt.Sprintf("Subkeys[%d].PublicKey.CreationTime is correct", i), func(t *testing.T) {
			assert.AssertEqualTimes(t, now, subkey.PublicKey.CreationTime)
		})

		t.Run(fmt.Sprintf("Subkeys[%d].Sig.CreationTime is correct", i), func(t *testing.T) {
			assert.AssertEqualTimes(t, now, subkey.Sig.CreationTime)
		})

		t.Run(fmt.Sprintf("Subkeys[%d].Sig.Hash matches the policy", i), func(t *testing.T) {
			assert.Equal(t, policy.SignatureHashFunction, subkey.Sig.Hash)
		})

		t.Run(fmt.Sprintf("Subkeys[%d] RSA key size is %d", i, policy.EncryptionSubkeyRsaKeyBits), func(t *testing.T) {
			var bitLength uint16
			bitLength, err = subkey.PublicKey.BitLength()
			if err != nil {
				t.Fatalf("failed to get subkey BitLength: %v", err)
			}

			if policy.EncryptionSubkeyRsaKeyBits != bitLength {
				t.Fatalf("bitlength expected %d, got %d", policy.EncryptionSubkeyRsaKeyBits, bitLength)
			}
		})
	}

	for name, identity := range generatedKey.Identities {
		t.Run(fmt.Sprintf("Identity[%s] expiry matches our policy", name), func(t *testing.T) {
			expectedExpiry := policy.NextExpiryTime(now)

			expires, gotExpiry := CalculateExpiry(
				generatedKey.PrimaryKey.CreationTime,
				identity.SelfSignature.KeyLifetimeSecs,
			)

			if !expires {
				t.Fatalf("expected expiry, but key doesn't expire")
			}

			if expectedExpiry != *gotExpiry {
				t.Fatalf("expected UID expiry %v, got %v", expectedExpiry, gotExpiry)
			}
		})
	}

	for i, subkey := range generatedKey.Subkeys {
		t.Run(fmt.Sprintf("Subkeys[%d] expiry matches our policy", i), func(t *testing.T) {
			expectedExpiry := policy.NextExpiryTime(now)

			expires, gotExpiry := CalculateExpiry(
				subkey.PublicKey.CreationTime,
				generatedKey.Identities["<jane@example.com>"].SelfSignature.KeyLifetimeSecs,
			)

			if !expires {
				t.Fatalf("expected expiry, but key doesn't expire")
			}

			if expectedExpiry != *gotExpiry {
				t.Fatalf("expected UID expiry %v, got %v", expectedExpiry, gotExpiry)
			}
		})
	}
}
