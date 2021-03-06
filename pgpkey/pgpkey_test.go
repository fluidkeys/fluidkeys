package pgpkey

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	insecurerand "math/rand"
	"testing"
	"time"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/packet"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/policy"
)

var mockRandom io.Reader = insecurerand.New(insecurerand.NewSource(0))

func TestTheTestHelperFunctions(t *testing.T) {
	pgpKey := loadExamplePgpKey(t)

	t.Run("example PGP key expected UID", func(t *testing.T) {
		expectedUid := exampleUid

		_, ok := pgpKey.Identities[expectedUid]

		if ok != true {
			t.Errorf("loaded example PGP key, didn't have UID %s", expectedUid)
		}
	})
}

func TestSlugMethod(t *testing.T) {

	t.Run("test slug method", func(t *testing.T) {
		pgpKey := loadExamplePgpKey(t)
		slug, err := pgpKey.Slug()
		if err != nil {
			t.Fatal(err)
		}
		assertEqual(t, "2018-08-23-test-example-com-0C10C4A26E9B1B46E713C8D2BEBF0628DAFF9F4B", slug)
	})

	t.Run("test slug method for multiple email addresses", func(t *testing.T) {
		pgpKey, err := LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
		assert.NoError(t, err)

		assert.Equal(t, 3, len(pgpKey.Identities))

		slug, err := pgpKey.Slug()
		assert.NoError(t, err)
		assertEqual(t, "2018-09-10-test3-example-com-7C18DE4DE47813568B243AC8719BD63EF03BDC20", slug)
	})
}

func TestEmailMethod(t *testing.T) {
	t.Run("returns only an email, stripping the '<' and '>'", func(t *testing.T) {
		pgpKey := loadExamplePgpKey(t)

		want := "test@example.com"
		got, err := pgpKey.Email()

		if err != nil {
			t.Fatalf("Error calling PgpKey.Email(): %v", err)
		}
		assertEqual(t, want, got)
	})

	t.Run("returns error when there are no identities", func(t *testing.T) {
		pgpKey, err := LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
		assert.NoError(t, err)

		// remove all identities
		pgpKey.Identities = make(map[string]*openpgp.Identity)

		assert.Equal(t, 0, len(pgpKey.Identities))

		_, err = pgpKey.Email()
		assert.GotError(t, err)
	})

	t.Run("with 3 valid identities ", func(t *testing.T) {
		pgpKey, err := LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
		assert.NoError(t, err)
		assert.Equal(t, 3, len(pgpKey.Identities))

		t.Run("if no identities are primary choose the oldest signature", func(t *testing.T) {

			setIsPrimary(false, pgpKey.Identities, "<test3@example.com>")
			setIsPrimary(false, pgpKey.Identities, "Example Name <another@example.com>")
			setIsPrimary(false, pgpKey.Identities, "unbracketedemail@example.com")

			email, err := pgpKey.Email()
			assert.NoError(t, err)

			assertEqual(t, "test3@example.com", email) // this has the oldest sig of all 3
		})
		t.Run("if one identity is flagged as primary choose that one", func(t *testing.T) {
			setIsPrimary(false, pgpKey.Identities, "<test3@example.com>")
			setIsPrimary(true, pgpKey.Identities, "Example Name <another@example.com>")
			setIsPrimary(false, pgpKey.Identities, "unbracketedemail@example.com")

			email, err := pgpKey.Email()
			assert.NoError(t, err)

			assertEqual(t, "another@example.com", email) // 2nd identity
		})

		t.Run("if two identities are primary choose the earliest", func(t *testing.T) {
			setIsPrimary(false, pgpKey.Identities, "<test3@example.com>")
			setIsPrimary(true, pgpKey.Identities, "Example Name <another@example.com>")
			setIsPrimary(true, pgpKey.Identities, "unbracketedemail@example.com")

			email, err := pgpKey.Email()
			assert.NoError(t, err)

			assertEqual(t, "another@example.com", email) // this has the oldest sig of the 2
		})
	})
}

func setIsPrimary(isPrimary bool, identities map[string]*openpgp.Identity, identityString string) {
	if id, inMap := identities[identityString]; inMap == true {
		id.SelfSignature.IsPrimaryId = &isPrimary
	} else {
		log.Panicf("couldn't find user id '%s' in map %v", identityString, identities)
	}

}

func TestEmailsMethod(t *testing.T) {
	pgpKey, err := LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
	assert.NoError(t, err)

	setIsPrimary(false, pgpKey.Identities, "<test3@example.com>")
	setIsPrimary(true, pgpKey.Identities, "Example Name <another@example.com>")
	setIsPrimary(false, pgpKey.Identities, "unbracketedemail@example.com")

	t.Run("returns sorted email addresses with allowUnbracketed=false", func(t *testing.T) {
		expected := []string{
			"another@example.com",
			"test3@example.com",
		}
		got := pgpKey.Emails(false)

		assert.AssertEqualSliceOfStrings(t, expected, got)
	})
	t.Run("returns sorted email addresses with allowUnbracketed=true", func(t *testing.T) {
		expected := []string{
			"another@example.com",
			"test3@example.com",
			"unbracketedemail@example.com",
		}
		got := pgpKey.Emails(true)

		assert.AssertEqualSliceOfStrings(t, expected, got)
	})

	t.Run("deduplicateEmails", func(t *testing.T) {
		t.Run("deduplicates identical emails", func(t *testing.T) {
			emails := []string{
				"john@example.com",
				"john@example.com",
			}
			expected := []string{
				"john@example.com",
			}

			assert.Equal(t, expected, deduplicateEmails(emails))
		})

		t.Run("deduplicates case variants, choosing first occurrence", func(t *testing.T) {
			emails := []string{
				"John@example.com",
				"john@example.com",
			}
			expected := []string{"John@example.com"}

			assert.Equal(t, expected, deduplicateEmails(emails))

			emails = []string{
				"john@example.com",
				"John@example.com",
			}
			expected = []string{"john@example.com"}

			assert.Equal(t, expected, deduplicateEmails(emails))
		})

		t.Run("deduplicates example with multiple addresses", func(t *testing.T) {
			emails := []string{
				"a@example.com",
				"a@example.com",
				"a@EXAMPLE.com",
				"A@example.com",
				"A@example.com",

				"B@example.com",
				"B@example.com",
				"b@example.com",
				"b@example.com",
				"b@EXAMPLE.com",
			}

			expected := []string{
				"a@example.com",
				"B@example.com",
			}

			assert.Equal(t, expected, deduplicateEmails(emails))
		})
	})
}

func TestFingerprintMethod(t *testing.T) {
	pgpKey := loadExamplePgpKey(t)

	t.Run("test PgpKey.FingerprintString() returns the right string", func(t *testing.T) {
		slug := pgpKey.Fingerprint().Hex()
		assertEqual(t, "0C10C4A26E9B1B46E713C8D2BEBF0628DAFF9F4B", slug)
	})
}

func TestRevocationCertificate(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	revokeTime := now.Add(time.Duration(24) * time.Hour)

	pgpKey, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	if err != nil {
		t.Fatalf("failed to generate PGP key in tests")
	}

	revocation, err := pgpKey.GetRevocationSignature(0, "no reason", revokeTime)
	if err != nil {
		t.Fatalf("Failed to call PgpKey.SerializeRevocation(): %v", err)
	}

	t.Run("revocation signature is of type 'key revocation'", func(t *testing.T) {
		gotSignatureType := revocation.SigType
		var expectedSignatureType packet.SignatureType = packet.SigTypeKeyRevocation

		if expectedSignatureType != gotSignatureType {
			t.Fatalf("expected signature type %v, got %v", expectedSignatureType, gotSignatureType)
		}
	})

	t.Run("revocation signature CreationTime is `revokeTime`", func(t *testing.T) {
		assert.Equal(t, revokeTime, revocation.CreationTime)
	})

	t.Run("revocation signature uses hash algorithm from our policy", func(t *testing.T) {
		assert.Equal(t, policy.SignatureHashFunction, revocation.Hash)
	})

	t.Run("revocation signature validates with PublicKey.VerifyRevocationSignature(..)", func(t *testing.T) {
		err = pgpKey.PrimaryKey.VerifyRevocationSignature(revocation)
		if err != nil {
			t.Fatalf("verify failed: %v", err)
		}

	})
}

func TestRevocationReasonSerializeParse(t *testing.T) {
	// Get the revocation signature, serialize it, then read it back to
	// test that the reason & reason text are set correctly.
	// Note: if this testing was in crypto/openpgp itself it could just
	// test the unexported outSubpackets field.

	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	revokeTime := now.Add(time.Duration(24) * time.Hour)

	pgpKey, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	if err != nil {
		t.Fatalf("failed to generate PGP key in tests")
	}

	var tests = []struct {
		reason     uint8
		reasonText string
	}{
		{0, "test text for reason 0"},
		{1, "test text for reason 1"},
		{2, "test text for reason 2"},
		{3, "test text for reason 3"},
		{32, "test text for reason 32"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("revocation reason #%d (%s) is serialized and deserialized correctly", test.reason, test.reasonText), func(t *testing.T) {
			revocation, err := pgpKey.GetRevocationSignature(test.reason, test.reasonText, revokeTime)
			if err != nil {
				t.Fatalf("Failed to call PgpKey.SerializeRevocation(): %v", err)
			}

			// We have to output then read back the signature to do this...
			buf := bytes.NewBuffer(nil)
			revocation.Serialize(buf)

			pkt, err := packet.Read(buf)
			if err != nil {
				t.Fatalf("packet.Read(revocation) failed: %v", err)
			}

			if parsedSig, ok := pkt.(*packet.Signature); ok {
				if parsedSig.RevocationReason == nil {
					t.Fatalf("expected reason %d, got nil", test.reason)
				}

				if *parsedSig.RevocationReason != test.reason {
					t.Fatalf("expected %d, got %d", test.reason, *parsedSig.RevocationReason)
				}

				if parsedSig.RevocationReasonText != test.reasonText {
					t.Fatalf("expected '%s', got '%s'", test.reasonText, parsedSig.RevocationReasonText)
				}
			} else {
				t.Fatalf("failed to cast back to Signature")
			}

		})
	}

	t.Run("PgpKey.ArmorRevocationCertificate returns an ascii armored public key containing a revocation signature", func(t *testing.T) {
		_, err := pgpKey.ArmorRevocationCertificate(revokeTime)
		if err != nil {
			t.Fatalf("error calling ArmorRevocationCertificate(): %v", err)
		}

	})
}

func TestSlugify(t *testing.T) {
	var tests = []struct {
		email    string
		wantSlug string
	}{
		{"test@example.com", "test-example-com"},
		{"test123@example.com", "test123-example-com"},
		{"test.foo@example.com", "test-foo-example-com"},
		{"test_foo@example.com", "test-foo-example-com"},
		{"test__foo@example.com", "test-foo-example-com"},
		{".@example.com", "-example-com"},
		{`" @"@example.com`, "-example-com"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("slugify(%s)", test.email), func(t *testing.T) {
			assertEqual(t, test.wantSlug, slugify(test.email))
		})

	}
}

func loadExamplePgpKey(t *testing.T) PgpKey {
	t.Helper()

	pgpKey, err := LoadFromArmoredPublicKey(examplePublicKey)
	if err != nil {
		t.Fatalf("failed to load example PGP key: %v", err)
	}
	return *pgpKey
}

func assertEqual(t *testing.T, want string, got string) {
	t.Helper()
	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}

func getSingleUid(identities map[string]*openpgp.Identity) string {
	var uids []string

	for uid := range identities {
		uids = append(uids, uid)
	}
	if len(uids) != 1 {
		log.Panicf("expected identities map to have 1 element, has %d", len(uids))
	}

	return uids[0]
}

func TestLoadFromArmoredPublicKey(t *testing.T) {
	pgpKey, err := LoadFromArmoredPublicKey(examplePublicKey)
	if err != nil {
		t.Fatalf("LoadFromArmoredPublicKey(..) failed: %v", err)
	}
	expected := fpr.MustParse("0C10 C4A2 6E9B 1B46 E713  C8D2 BEBF 0628 DAFF 9F4B")
	got := pgpKey.Fingerprint()
	if got != expected {
		t.Fatalf("loaded pgp key but it had unexpected fingerprint. exprted: %v, got: %v", expected, got)
	}
}

func TestLoadFromArmoredEncryptedPrivateKey(t *testing.T) {
	pgpKey, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey2, "test2")
	if err != nil {
		t.Fatalf("LoadFromArmoredEncryptedPrivateKey(..) failed: %v", err)
	}

	t.Run("fingerprint matches", func(t *testing.T) {
		expectedFingerprint := exampledata.ExampleFingerprint2
		got := pgpKey.Fingerprint()
		if got != expectedFingerprint {
			t.Fatalf("expectected fingerprint: %v, got: %v", expectedFingerprint, got)
		}
	})

	t.Run("loaded key has been decrypted", func(t *testing.T) {
		if pgpKey.PrivateKey.Encrypted == true {
			t.Fatalf("loaded pgp key but it's still encrypted")
		}
	})

	for i, subkey := range pgpKey.Subkeys {
		t.Run(fmt.Sprintf("loaded key.Subkeys[%d] has been decrypted", i), func(t *testing.T) {
			if subkey.PrivateKey.Encrypted == true {
				t.Fatalf("subkey still encrypted")
			}
		})
	}

	t.Run("bad password returns IncorrectPassword error type", func(t *testing.T) {
		_, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey2, "badpassword")
		if err == nil {
			t.Fatalf("err should have been set for bad password.")
		}

		if _, ok := err.(*IncorrectPassword); !ok {
			t.Fatalf("expected err.(type) = IncorrectPassword, got %v", err)
		}

		expectedText := "incorrect password: openpgp: invalid data: private key sha1 failure"
		gotText := err.Error()

		if expectedText != gotText {
			t.Fatalf("expected '%s', got '%s'", expectedText, gotText)

		}
	})

	t.Run("load fails with invalid ascii armor", func(t *testing.T) {
		_, err := LoadFromArmoredEncryptedPrivateKey("INVALID ASCII ARMOR", "badpassword")
		if err == nil {
			t.Fatalf("err should have been set for invalid ascii armor")
		}
	})
}

func TestEncryptionSubkey(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	thirtyDaysAgo := now.Add(-time.Duration(24*30) * time.Hour)
	sixtyDaysAgo := now.Add(-time.Duration(24*60) * time.Hour)
	tenDaysFromNow := now.Add(time.Duration(24*10) * time.Hour)
	thirtyDaysFromNow := now.Add(time.Duration(24*30) * time.Hour)

	sixtyDaysAgoAddFortyFive := sixtyDaysAgo.Add(time.Duration(45*24) * time.Hour)

	subkeyTests := []subkeyConfig{
		{
			// valid, created 60 days ago
			expectedValid:         true,
			keyCreationTime:       sixtyDaysAgo,
			signatureCreationTime: sixtyDaysAgo,
			expiryTime:            &thirtyDaysFromNow, // valid, within expiry
			revoked:               false,
			flagsValid:            true,
			encryptFlags:          true,
		},
		{
			// valid, created 30 days ago (most recent should be selected)
			expectedValid:         true,
			keyCreationTime:       thirtyDaysAgo,
			signatureCreationTime: thirtyDaysAgo,
			expiryTime:            &thirtyDaysFromNow, // valid, within expiry
			revoked:               false,
			flagsValid:            true,
			encryptFlags:          true,
		},
		{
			// valid, no expiry
			expectedValid:         true,
			keyCreationTime:       thirtyDaysAgo,
			signatureCreationTime: thirtyDaysAgo,
			expiryTime:            nil,
			revoked:               false,
			flagsValid:            true,
			encryptFlags:          true,
		},
		{
			// valid, key and sig created just now
			expectedValid:         true,
			keyCreationTime:       now,
			signatureCreationTime: now,
			expiryTime:            &thirtyDaysFromNow, // valid, within expiry
			revoked:               false,
			flagsValid:            true,
			encryptFlags:          true,
		},
		{
			// invalid, created in the future
			expectedValid:         false,
			keyCreationTime:       tenDaysFromNow,
			signatureCreationTime: tenDaysFromNow,
			expiryTime:            &thirtyDaysFromNow,
			revoked:               false,
			flagsValid:            true,
			encryptFlags:          true,
		},
		{
			// invalid, *key* creation time vs signature creation time
			//
			// expiry is calculated as:
			// *key creation time* + number of seconds
			// NOT *signature creation time*
			//
			// this test ensures code calculates off the correct
			// reference point.
			expectedValid:         false,
			keyCreationTime:       sixtyDaysAgo,
			signatureCreationTime: thirtyDaysAgo,
			expiryTime:            &sixtyDaysAgoAddFortyFive,
			revoked:               false,
			flagsValid:            true,
			encryptFlags:          true,
		},
		{
			// invalid, expired
			expectedValid:         false,
			keyCreationTime:       sixtyDaysAgo,
			signatureCreationTime: sixtyDaysAgo,
			expiryTime:            &thirtyDaysAgo, // expired
			revoked:               false,
			flagsValid:            true,
			encryptFlags:          true,
		},
		{
			// invalid, revoked
			expectedValid:         false,
			keyCreationTime:       sixtyDaysAgo,
			signatureCreationTime: sixtyDaysAgo,
			expiryTime:            &thirtyDaysFromNow, // valid, within expiry
			revoked:               true,
			flagsValid:            true,
			encryptFlags:          true,
		},
		{
			// invalid, can't do encryption
			expectedValid:         false,
			keyCreationTime:       sixtyDaysAgo,
			signatureCreationTime: sixtyDaysAgo,
			expiryTime:            &thirtyDaysFromNow, // valid, within expiry
			revoked:               false,
			flagsValid:            true,
			encryptFlags:          false,
		},
		{
			// invalid, FlagsValid=false
			expectedValid:         false,
			keyCreationTime:       sixtyDaysAgo,
			signatureCreationTime: sixtyDaysAgo,
			expiryTime:            &thirtyDaysFromNow, // valid, within expiry
			revoked:               false,
			flagsValid:            false,
			encryptFlags:          true,
		},
	}

	pgpKey, err := makeKeyWithSubkeys(t, subkeyTests, now)
	if err != nil {
		t.Fatal(err)
	}

	for i, subkey := range pgpKey.Subkeys {
		t.Run(fmt.Sprintf("isEncryptionSubkeyValid(subkeyConfig %d)", i), func(t *testing.T) {
			assertSubkeyValidity(subkey, subkeyTests[i].expectedValid, now, t)
		})
	}

	t.Run("validEncryptionSubkeys filters valid keys", func(t *testing.T) {
		var expectedSubkeys []openpgp.Subkey // we don't know these until they've been generated

		for i, subkeyConfig := range subkeyTests {
			if subkeyConfig.expectedValid {
				expectedSubkeys = append(expectedSubkeys, pgpKey.Subkeys[i])
			}
		}

		gotSubkeys := pgpKey.validEncryptionSubkeys(now)
		if len(gotSubkeys) != len(expectedSubkeys) {
			t.Logf("gpKey.subkeys: %v", pgpKey.Subkeys)
			t.Fatalf("expected %d valid subkeys, got %d: %v", len(expectedSubkeys), len(gotSubkeys), gotSubkeys)
		}

		for i := range expectedSubkeys {
			if expectedSubkeys[i] != gotSubkeys[i] {
				t.Fatalf("expectedSubkeys[%d] != gotSubkeys[%d]. expected: %v, got: %v",
					i, i, expectedSubkeys[i], gotSubkeys[i])
			}
		}

	})

	t.Run("EncryptionSubkey selects most recent subkey", func(t *testing.T) {
		expectedKey := pgpKey.Subkeys[3]
		gotKey := pgpKey.EncryptionSubkey(now)

		if gotKey == nil {
			t.Fatalf("expected a subkey, got nil")
		}

		if gotKey.PublicKey.KeyId != expectedKey.PublicKey.KeyId {
			t.Fatalf("expected: %v (created %v), got: %v (created %v)",
				expectedKey,
				expectedKey.Sig.CreationTime,
				gotKey,
				gotKey.Sig.CreationTime)
		}
	})

	t.Run("with no valid subkeys", func(t *testing.T) {
		stashedSubkeys := pgpKey.Subkeys
		pgpKey.Subkeys = []openpgp.Subkey{} // delete all the subkeys so there aren't any valid ones

		t.Run("validEncryptionSubkeys() returns empty", func(t *testing.T) {
			gotKeys := pgpKey.validEncryptionSubkeys(now)
			if len(gotKeys) != 0 {
				t.Fatalf("expected empty slice, got %v", gotKeys)
			}
		})

		t.Run("EncryptionSubkey() returns nil", func(t *testing.T) {
			gotKey := pgpKey.EncryptionSubkey(now)

			if gotKey != nil {
				t.Fatalf("expected nil for no valid keys, got %v", gotKey)
			}
		})

		pgpKey.Subkeys = stashedSubkeys
	})

}

type subkeyConfig struct {
	expectedValid         bool
	keyCreationTime       time.Time
	signatureCreationTime time.Time
	expiryTime            *time.Time
	revoked               bool
	flagsValid            bool
	encryptFlags          bool
}

func makeKeyWithSubkeys(t *testing.T, subkeyConfigs []subkeyConfig, now time.Time) (*PgpKey, error) {
	t.Helper()

	pgpKey, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	if err != nil {
		t.Fatalf("failed to generate PGP key in tests")
	}
	pgpKey.Subkeys = []openpgp.Subkey{} // delete existing subkey

	config := packet.Config{
		Rand: mockRandom,
	}

	for i, subkeyConfig := range subkeyConfigs {
		privateKey, err := rsa.GenerateKey(config.Random(), 1024)
		if err != nil {
			t.Fatalf("failed to generate subkey from subkeyConfig[%d]: %v", i, err)
		}

		var expiryDuration *uint32
		if subkeyConfig.expiryTime != nil {
			tmp := uint32(subkeyConfig.expiryTime.Sub(subkeyConfig.keyCreationTime).Seconds())
			expiryDuration = &tmp
		} else {
			expiryDuration = nil
		}
		subkey := openpgp.Subkey{
			PublicKey:  packet.NewRSAPublicKey(now, &privateKey.PublicKey),
			PrivateKey: packet.NewRSAPrivateKey(now, privateKey),
			Sig: &packet.Signature{
				CreationTime:              subkeyConfig.signatureCreationTime,
				KeyLifetimeSecs:           expiryDuration,
				SigType:                   packet.SigTypeSubkeyBinding,
				PubKeyAlgo:                packet.PubKeyAlgoRSA,
				Hash:                      config.Hash(),
				FlagsValid:                subkeyConfig.flagsValid,
				FlagEncryptStorage:        subkeyConfig.encryptFlags,
				FlagEncryptCommunications: subkeyConfig.encryptFlags,
				IssuerKeyId:               &pgpKey.PrimaryKey.KeyId,
			},
		}

		subkey.PublicKey.CreationTime = subkeyConfig.keyCreationTime
		subkey.PublicKey.IsSubkey = true
		subkey.PrivateKey.IsSubkey = true

		err = subkey.Sig.SignKey(subkey.PublicKey, pgpKey.PrivateKey, &config)
		if err != nil {
			t.Fatalf("failed to sign subkey: %v", err)
		}

		if subkeyConfig.revoked {
			subkey.Sig = &packet.Signature{
				SigType:     packet.SigTypeSubkeyRevocation,
				Hash:        config.Hash(),
				IssuerKeyId: &pgpKey.PrimaryKey.KeyId,
			}
		}

		err = subkey.Sig.SignKey(subkey.PublicKey, pgpKey.PrivateKey, &config)
		if err != nil {
			t.Fatalf("failed to create subkey revocation sig: %v", err)
		}

		pgpKey.Subkeys = append(pgpKey.Subkeys, subkey)
	}
	return pgpKey, nil
}

func TestCreateNewEncryptionSubkey(t *testing.T) {

	pgpKey, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	if err != nil {
		t.Fatalf("failed to generate PGP key in tests")
	}

	now := pgpKey.PrimaryKey.CreationTime.Add(time.Duration(1) * time.Hour)
	thirtyDaysFromNow := now.Add(time.Duration(24*30) * time.Hour)

	err = pgpKey.SetPreferredHashAlgorithms(policy.AdvertiseHashPreferences, now) // workaround as example private key doesn't have hash prefs
	if err != nil {
		t.Fatalf("failed to refresh self sigs: %v", err)
	}

	pgpKey.Subkeys = []openpgp.Subkey{} // delete existing subkey

	err = pgpKey.CreateNewEncryptionSubkey(thirtyDaysFromNow, now, mockRandom)
	if err != nil {
		t.Fatalf("Error creating subkey: %v", err)
	}

	gotSubKey := pgpKey.EncryptionSubkey(now)

	t.Run("creates a valid subkey", func(t *testing.T) {
		if gotSubKey == nil {
			t.Fatalf("Expected to be able to get a subkey, but couldn't")
		} else {
			t.Run("with flags set correctly", func(t *testing.T) {
				if gotSubKey.Sig.FlagsValid != true {
					t.Fatalf("FlagsValid is false, expected true")
				}
				if gotSubKey.Sig.FlagEncryptStorage != true {
					t.Fatalf("FlagEncryptStorage is false, expected true")
				}
				if gotSubKey.Sig.FlagEncryptCommunications != true {
					t.Fatalf("FlagEncryptCommunications is false, expected true")
				}
			})

			t.Run("with correct signature creation time", func(t *testing.T) {
				got := gotSubKey.Sig.CreationTime
				if got != now {
					t.Fatalf("expected %v, got %v", now, got)
				}
			})

			t.Run("with subkey binding signature hash matching our policy", func(t *testing.T) {
				got := gotSubKey.Sig.Hash
				assert.Equal(t, got, policy.SignatureHashFunction)
			})

			t.Run("with correction public key creation time", func(t *testing.T) {
				got := gotSubKey.PublicKey.CreationTime
				if got != now {
					t.Fatalf("expected %v, got %v", now, got)
				}
			})
		}
	})

	t.Run("with a valid signature", func(t *testing.T) {
		err := pgpKey.PrimaryKey.VerifyKeySignature(gotSubKey.PublicKey, gotSubKey.Sig)

		if err != nil {
			t.Fatalf("Subkey signature is invalid: " + err.Error())
		}
	})

	t.Run("can encrypt something", func(t *testing.T) {
		config := packet.Config{
			Time: func() time.Time { return now },
		}

		outputCipherText := bytes.NewBuffer(nil)
		w, err := openpgp.Encrypt(
			outputCipherText,
			[]*openpgp.Entity{&pgpKey.Entity},
			&pgpKey.Entity,
			nil,
			&config,
		)

		if err != nil {
			t.Fatalf("Error creating the encrypt writer: %s", err)
		}

		const message = "A test message"
		_, err = w.Write([]byte(message))
		if err != nil {
			t.Fatalf("Error writing plaintext: %s", err)
		}
		err = w.Close()
		if err != nil {
			t.Fatalf("Error closing WriteCloser: %s", err)
		}
	})

}

func TestExpireSubkey(t *testing.T) {
	key, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	if err != nil {
		t.Fatalf("failed to load key for testing: %v", err)
	}

	now := time.Date(2018, 10, 15, 0, 0, 0, 0, time.UTC)
	subkey := key.EncryptionSubkey(now)
	if subkey == nil {
		t.Fatalf("failed to get valid subkey for testing")
	}

	originalSubkeySignatureCreationTime := subkey.Sig.CreationTime
	assertSubkeyValidity(*subkey, true, now, t)

	key.ExpireSubkey(subkey.PublicKey.KeyId, now)

	t.Run("new subkey binding signature CreationTime is more recent that existing", func(t *testing.T) {
		if !subkey.Sig.CreationTime.After(originalSubkeySignatureCreationTime) {
			t.Fatalf("Expected %v to be after %v", subkey.Sig.CreationTime, originalSubkeySignatureCreationTime)
		}
	})

	assertSubkeyValidity(*subkey, false, now, t)
}

func TestUpdateSubkeyValidUntil(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	validUntil := now.Add(-time.Duration(10) * time.Second)
	sixtyDaysAgo := now.Add(-time.Duration(24*60) * time.Hour)
	thirtyDaysFromNow := now.Add(time.Duration(24*30) * time.Hour)

	subkeyConfigs := []subkeyConfig{
		{
			keyCreationTime:       sixtyDaysAgo,
			signatureCreationTime: sixtyDaysAgo,
			expiryTime:            &thirtyDaysFromNow, // valid, within expiry
			revoked:               false,
			flagsValid:            true,
			encryptFlags:          true,
		},
	}

	pgpKey, err := makeKeyWithSubkeys(t, subkeyConfigs, now)
	if err != nil {
		t.Fatal(err)
	}

	subkey := pgpKey.EncryptionSubkey(now)
	assertSubkeyValidity(*subkey, true, now, t)

	err = pgpKey.UpdateSubkeyValidUntil(subkey.PublicKey.KeyId, validUntil, now)
	if err != nil {
		t.Fatalf("Error updating subkey expiry to now: " + err.Error())
	}

	t.Run("new subkey binding signature CreationTime is `now`", func(t *testing.T) {
		assert.Equal(t, now, subkey.Sig.CreationTime)
	})

	t.Run("subkey expiry time is now `validUntil`", func(t *testing.T) {
		hasExpiry, expiry := SubkeyExpiry(*subkey)
		if hasExpiry != true {
			t.Fatalf("Expected an expiry, haven't got one")
		}
		if *expiry != validUntil {
			t.Fatalf("Expected expiry to be %v, got %v", validUntil, *expiry)
		}
	})
	t.Run("new subkey binding signature validates", func(t *testing.T) {
		err := pgpKey.PrimaryKey.VerifyKeySignature(subkey.PublicKey, subkey.Sig)
		if err != nil {
			t.Fatalf("Subkey signature is invalid: " + err.Error())
		}
	})

	t.Run("new subkey binding signature uses hash algorithm from our policy", func(t *testing.T) {
		got := subkey.Sig.Hash
		assert.Equal(t, got, policy.SignatureHashFunction)
	})
}

func TestSetPreferredMethods(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)

	key, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	if err != nil {
		t.Fatalf("failed to load example key")
	}
	publicKeyOnly, err := LoadFromArmoredPublicKey(exampledata.ExamplePrivateKey3)
	if err != nil {
		t.Fatalf("failed to load example key")
	}

	var methods = []struct {
		name                    string
		setter                  func([]uint8, time.Time) error // the function we're testing
		setterWithoutPrivateKey func([]uint8, time.Time) error
		getter                  func(*openpgp.Identity) []uint8 // a lambda func to read back the preferences
	}{
		{
			name:                    "SetPreferredSymmetricAlgorithms",
			setter:                  key.SetPreferredSymmetricAlgorithms,
			setterWithoutPrivateKey: publicKeyOnly.SetPreferredSymmetricAlgorithms,
			getter:                  func(identity *openpgp.Identity) []uint8 { return identity.SelfSignature.PreferredSymmetric },
		},
		{
			name:                    "SetPreferredHashAlgorithms",
			setter:                  key.SetPreferredHashAlgorithms,
			setterWithoutPrivateKey: publicKeyOnly.SetPreferredHashAlgorithms,
			getter:                  func(identity *openpgp.Identity) []uint8 { return identity.SelfSignature.PreferredHash },
		},
		{
			name:                    "SetPreferredCompressionAlgorithms",
			setter:                  key.SetPreferredCompressionAlgorithms,
			setterWithoutPrivateKey: publicKeyOnly.SetPreferredCompressionAlgorithms,
			getter:                  func(identity *openpgp.Identity) []uint8 { return identity.SelfSignature.PreferredCompression },
		},
	}

	for _, method := range methods {
		t.Run(method.name, func(t *testing.T) {
			newPreferredAlgos := []uint8{1, 2, 3}

			err := method.setter(newPreferredAlgos, now)
			if err != nil {
				t.Fatalf("%s gave error: %v", method.name, err)
			}

			for name, identity := range key.Identities {
				t.Run(fmt.Sprintf("%s: preferences read back correctly", name), func(t *testing.T) {
					gotPreferredAlgos := method.getter(identity)

					if fmt.Sprintf("%#v", gotPreferredAlgos) != fmt.Sprintf("%#v", newPreferredAlgos) {
						t.Fatalf("Expected to read back prefs %v but got %v", newPreferredAlgos, gotPreferredAlgos)
					}
				})

				t.Run(fmt.Sprintf("%s: self signature creation time is `now`", name), func(t *testing.T) {
					if identity.SelfSignature.CreationTime != now {
						t.Fatalf("Expected identity.SelfSignature.CreationTime to be now (%v), got %v", now, identity.SelfSignature.CreationTime)
					}
				})

				t.Run(fmt.Sprintf("%s: self signature validates", name), func(t *testing.T) {
					err := key.PrimaryKey.VerifyUserIdSignature(name, key.PrimaryKey, identity.SelfSignature)
					if err != nil {
						t.Fatalf("user id self signature is invalid: %v,", err)
					}
				})

			}
			t.Run(fmt.Sprintf("%s fails if private key isn't present", method.name), func(t *testing.T) {
				err := method.setterWithoutPrivateKey(newPreferredAlgos, now)
				if err == nil {
					t.Fatalf("expected error if private key is missing")
				}
			})
		})
	}

}

func TestRefreshUserIdSelfSignatures(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	key, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	if err != nil {
		t.Fatalf("failed to load example key")
	}

	err = key.RefreshUserIdSelfSignatures(now)
	if err != nil {
		t.Fatalf("got error: %v", err)
	}

	for name, identity := range key.Identities {
		t.Run(fmt.Sprintf("%s: self signature creation time is `now`", name), func(t *testing.T) {
			if identity.SelfSignature.CreationTime != now {
				t.Fatalf("Expected identity.SelfSignature.Creation to be now (%v), got %v", now, identity.SelfSignature.CreationTime)
			}
		})

		t.Run(fmt.Sprintf("%s: self signature validates", name), func(t *testing.T) {
			err := key.PrimaryKey.VerifyUserIdSignature(name, key.PrimaryKey, identity.SelfSignature)
			if err != nil {
				t.Fatalf("user id self signature is invalid: %v,", err)
			}
		})

		t.Run(fmt.Sprintf("%s: self signature uses SHA512", name), func(t *testing.T) {
			if identity.SelfSignature.Hash != crypto.SHA512 {
				t.Fatalf("expected signature to use SHA512, got %v", identity.SelfSignature.Hash)
			}
		})
	}

	publicKeyOnly, err := LoadFromArmoredPublicKey(exampledata.ExamplePrivateKey3)
	if err != nil {
		t.Fatalf("failed to load example key")
	}

	t.Run("fails if private key isn't present", func(t *testing.T) {
		err := publicKeyOnly.RefreshUserIdSelfSignatures(now)
		assert.GotError(t, err)
	})
}

func TestRefreshSubkeyBindingSignature(t *testing.T) {
	key, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	if err != nil {
		t.Fatalf("failed to load example key")
	}

	publicKeyOnly, err := LoadFromArmoredPublicKey(exampledata.ExamplePrivateKey3)
	if err != nil {
		t.Fatalf("failed to load example key")
	}

	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)

	err = key.RefreshSubkeyBindingSignature(0x409F66EB6D1336A7, now)
	if err != nil {
		t.Fatalf("got error: %v", err)
	}

	for _, subkey := range key.Subkeys {
		keyid := subkey.PublicKey.KeyId

		t.Run(fmt.Sprintf("Subkey[0x%X]: self signature creation time is `now`", keyid), func(t *testing.T) {
			if subkey.Sig.CreationTime != now {
				t.Fatalf("Expected subkey.Sig.Creation to be now (%v), got %v", now, subkey.Sig.CreationTime)
			}
		})

		t.Run(fmt.Sprintf("Subkey[0x%X]: self signature validates", keyid), func(t *testing.T) {
			err := key.PrimaryKey.VerifyKeySignature(subkey.PublicKey, subkey.Sig)
			if err != nil {
				t.Fatalf("subkey binding signature is invalid: %v,", err)
			}
		})

		t.Run(fmt.Sprintf("Subkey[0x%X]: hash function is SHA512", keyid), func(t *testing.T) {
			if subkey.Sig.Hash != crypto.SHA512 {
				t.Fatalf("subkey binding signature isn't SHA512: %v", subkey.Sig.Hash)
			}
		})
	}

	t.Run("fails with invalid Subkeyid", func(t *testing.T) {
		err := publicKeyOnly.RefreshSubkeyBindingSignature(0x0000000000000000, now)
		assert.GotError(t, err)
	})

	t.Run("fails if private key isn't present", func(t *testing.T) {
		err := publicKeyOnly.RefreshSubkeyBindingSignature(0x409F66EB6D1336A7, now)
		assert.GotError(t, err)
	})
}

func TestSubkey(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	sixtyDaysAgo := now.Add(-time.Duration(24*60) * time.Hour)
	thirtyDaysAgo := now.Add(-time.Duration(24*30) * time.Hour)
	tenDaysAgo := now.Add(-time.Duration(24*10) * time.Hour)
	thirtyDaysFromNow := now.Add(time.Duration(24*30) * time.Hour)

	subkeyConfigs := []subkeyConfig{
		{
			expectedValid:         false,
			keyCreationTime:       sixtyDaysAgo,
			signatureCreationTime: thirtyDaysAgo,
			expiryTime:            &tenDaysAgo,
			revoked:               true,
			flagsValid:            true,
			encryptFlags:          true,
		},
		{
			expectedValid:         true,
			keyCreationTime:       tenDaysAgo,
			signatureCreationTime: tenDaysAgo,
			expiryTime:            &thirtyDaysFromNow,
			revoked:               false,
			flagsValid:            true,
			encryptFlags:          true,
		},
	}

	pgpKey, err := makeKeyWithSubkeys(t, subkeyConfigs, now)
	if err != nil {
		t.Fatal(err)
	}

	for i, subkey := range pgpKey.Subkeys {
		t.Run(fmt.Sprintf("isEncryptionSubkeyValid(subkeyConfig %d)", i), func(t *testing.T) {
			assertSubkeyValidity(subkey, subkeyConfigs[i].expectedValid, now, t)
		})
	}

	t.Run("returns a subkey", func(t *testing.T) {
		wantSubkey := pgpKey.Subkeys[0]

		gotSubkey, error := pgpKey.Subkey(wantSubkey.PublicKey.KeyId)
		assert.NoError(t, error)

		if *gotSubkey != wantSubkey {
			t.Fatalf(
				"Expected subkey %v, but got subkey %v",
				wantSubkey.PublicKey.KeyIdString(),
				gotSubkey.PublicKey.KeyIdString(),
			)
		}
	})

	t.Run("errors if passed an invalid KeyId", func(t *testing.T) {
		gotSubkey, error := pgpKey.Subkey(uint64(0xF423F))
		assert.GotError(t, error)
		if gotSubkey != nil {
			t.Fatalf("expected no subkey, but got %v\n", gotSubkey.PublicKey.KeyIdString())
		}
	})
}

func assertSubkeyValidity(subkey openpgp.Subkey, expectedIsValid bool, now time.Time, t *testing.T) {
	t.Helper()
	gotIsValid := isEncryptionSubkeyValid(subkey, now)

	if expectedIsValid != gotIsValid {
		t.Errorf("Expected valid=%v, got %v", expectedIsValid, gotIsValid)
	}
}

func TestUpdateExpiryForAllUserIds(t *testing.T) {

	pgpKey, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	if err != nil {
		t.Fatalf("Failed to load example test data: %v", err)
	}

	originalSelfSignatureCreationTime := pgpKey.Identities["<test3@example.com>"].SelfSignature.CreationTime

	now := originalSelfSignatureCreationTime.Add(time.Duration(24) * time.Hour)
	newValidUntil := now.Add(time.Duration(24) * time.Hour)

	err = pgpKey.UpdateExpiryForAllUserIds(newValidUntil, now)
	if err != nil {
		t.Fatalf("Error updating expiry for user ids: %v\n", err)
	}

	newSelfSignature := pgpKey.Identities["<test3@example.com>"].SelfSignature

	t.Run("signs with a valid signature", func(t *testing.T) {
		err := pgpKey.PrimaryKey.VerifyUserIdSignature(
			pgpKey.Identities["<test3@example.com>"].Name,
			pgpKey.PrimaryKey,
			newSelfSignature,
		)
		if err != nil {
			t.Fatalf("new self signature is invalid: " + err.Error())
		}
	})

	t.Run("new self signature creation time is `now`", func(t *testing.T) {
		assert.Equal(t, now, newSelfSignature.CreationTime)
	})

	t.Run("new self signature creation time is more recent that existing", func(t *testing.T) {
		if !newSelfSignature.CreationTime.After(originalSelfSignatureCreationTime) {
			t.Fatalf("Expected %v to be after %v", newSelfSignature.CreationTime, originalSelfSignatureCreationTime)
		}
	})

	t.Run("new self signature uses hash according to our policy", func(t *testing.T) {
		assert.Equal(t, policy.SignatureHashFunction, newSelfSignature.Hash)
	})

	t.Run("sets all identities to expire at correct time", func(t *testing.T) {
		expectedKeyLifetimeSeconds := uint32(newValidUntil.Sub(pgpKey.PrimaryKey.CreationTime).Seconds())

		for _, uid := range pgpKey.Identities {
			got := uid.SelfSignature.KeyLifetimeSecs
			if expectedKeyLifetimeSeconds != *uid.SelfSignature.KeyLifetimeSecs {
				t.Fatalf("Expected %d, got %d", expectedKeyLifetimeSeconds, got)
			}
		}
	})
}

func TestMethodsRequiringDecryptedPrivateKey(t *testing.T) {
	t.Run("error when passed an encrypted key", func(t *testing.T) {
		pgpKey, err := LoadFromArmoredPublicKey(exampledata.ExamplePrivateKey3)
		if err != nil {
			t.Fatalf("Failed to load example test data: %v", err)
		}

		_, err = pgpKey.ArmorPrivate("password")
		assert.GotError(t, err)

		err = pgpKey.UpdateExpiryForAllUserIds(time.Now(), time.Now())
		assert.GotError(t, err)

		err = pgpKey.CreateNewEncryptionSubkey(time.Now(), time.Now(), mockRandom)
		assert.GotError(t, err)

		err = pgpKey.UpdateSubkeyValidUntil(999, time.Now(), time.Now())
		assert.GotError(t, err)
	})

	t.Run("error when passed onlt a public key", func(t *testing.T) {
		pgpKey, err := LoadFromArmoredPublicKey(examplePublicKey)
		if err != nil {
			t.Fatalf("Failed to load example test data: %v", err)
		}

		_, err = pgpKey.ArmorPrivate("password")
		assert.GotError(t, err)

		err = pgpKey.UpdateExpiryForAllUserIds(time.Now(), time.Now())
		assert.GotError(t, err)

		err = pgpKey.CreateNewEncryptionSubkey(time.Now(), time.Now(), mockRandom)
		assert.GotError(t, err)

		err = pgpKey.UpdateSubkeyValidUntil(999, time.Now(), time.Now())
		assert.GotError(t, err)
	})
}

const examplePublicKey string = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EW358xgEEAMv+L3f9UqB6FKWamHIBLxs615iVmPZwr0MvLg2nQ8TZJHTpLyIp
0JKjsPSQd5ivKGulkkV81ztHKY8aeoyfAqslryGLfUhYLtm8ZxLwLX/RywUgptTx
BHkZSTKbFg2zwB75//G3sytwfc5jYwpBQEb4Kp/RLvCRKMZo75AVMSw/ABEBAAG0
Ejx0ZXN0QGV4YW1wbGUuY29tPoiiBBMBCAAWBQJbfnzGCRC+vwYo2v+fSwIbAwIZ
AQAAJ5YEAIyWYOxx1AN+nfuSfAweykm6E8ilLYkDeSdXP0p13svdfRydJNT0aZqJ
qOs0JGB2FRzOh8dM3GzA4AhYPfImv71EWMms6bHI5xnWebNOY17vOc7r0nIMfRpC
5BbATpcFSpeTUpxcsoAXHgIyNz8rn/JQJcR64u7lnIJ7SeAJqRKsuI0EW358xgEE
AMmRyEOQPU/OWt9ZEB2NWJcLcbwE31PzORlvHy2kHUQ32tE8YufBP+XUuOsEtgqQ
IaHwszbgQQZWR0RU1p7bNOEcSG5nm6Fskf0w2DNBH25UgLhZ/6cPyvlYk9T2LEfm
/wzD+/I7SoCZc5l86c8eVpSnHxjZ7dhpbHGFdsGDiiDLABEBAAGInwQYAQgAEwUC
W358xgkQvr8GKNr/n0sCGwwAAAABBACgBKQXRj/SZaxY+IEQfBdRGYlGGUlhxxPV
2941o2lV5It+e1NgJHwzS8vtNyR1bNUmxociVXuvbg7MJiQo+fkFdFmTZU4hExjg
fd/CgPcUg8OUKnK9aP5FoDz3rTlLkDlKVOXzHGn5Rg+MNeh+i9tnBDS3CbPvpI7M
lj2PQbxhrA==
=5RCD
-----END PGP PUBLIC KEY BLOCK-----`

const exampleUid string = "<test@example.com>"
