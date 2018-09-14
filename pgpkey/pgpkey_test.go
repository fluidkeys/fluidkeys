package pgpkey

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/packet"

	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/fingerprint"
)

func TestTheTestHelperFunctions(t *testing.T) {
	pgpKey := loadExamplePgpKey(t)

	t.Run("example PGP key expected UID", func(*testing.T) {
		expectedUid := exampleUid

		_, ok := pgpKey.Identities[expectedUid]

		if ok != true {
			t.Errorf("loaded example PGP key, didn't have UID %s", expectedUid)
		}
	})
}

func TestSlugMethod(t *testing.T) {
	pgpKey := loadExamplePgpKey(t)

	t.Run("test slug method", func(*testing.T) {
		slug, err := pgpKey.Slug()
		if err != nil {
			t.Fatal(err)
		}
		assertEqual(t, "2018-08-23-test-example-com-0C10C4A26E9B1B46E713C8D2BEBF0628DAFF9F4B", slug)
	})
}

func TestEmailMethod(t *testing.T) {
	t.Run("returns only an email, stripping the '<' and '>'", func(*testing.T) {
		pgpKey := loadExamplePgpKey(t)

		want := "test@example.com"
		got, err := pgpKey.Email()

		if err != nil {
			t.Fatalf("Error calling PgpKey.Email(): %v", err)
		}
		assertEqual(t, want, got)
	})
}

func TestEmailsMethod(t *testing.T) {
	pgpKey, err := LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
	if err != nil {
		t.Fatalf("Failed to load example test data: %v", err)
	}

	t.Run("returns sorted email addresses with allowUnbracketed=false", func(t *testing.T) {
		expected := []string{
			"another@example.com",
			"test3@example.com",
		}
		got := pgpKey.Emails(false)

		if len(got) != len(expected) {
			t.Fatalf("Expected %d emails, got %d: %v", len(expected), len(got), got)
		}

		for i := range expected {
			if expected[i] != got[i] {
				t.Fatalf("expected[%d] = '%s', got = '%s'", i, expected[i], got[i])
			}
		}
	})
	t.Run("returns sorted email addresses with allowUnbracketed=true", func(t *testing.T) {
		expected := []string{
			"another@example.com",
			"test3@example.com",
			"unbracketedemail@example.com",
		}
		got := pgpKey.Emails(true)

		if len(got) != len(expected) {
			t.Fatalf("Expected %d emails, got %d: %v", len(expected), len(got), got)
		}

		for i := range expected {
			if expected[i] != got[i] {
				t.Fatalf("expected[%d] = '%s', got = '%s'", i, expected[i], got[i])
			}
		}
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
	pgpKey, err := generateInsecure("revoke.test@example.com")
	if err != nil {
		t.Fatalf("failed to generate PGP key in tests")
	}

	revocation, err := pgpKey.GetRevocationSignature(0, "no reason")
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

	pgpKey, err := generateInsecure("revoke.test@example.com")
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
			revocation, err := pgpKey.GetRevocationSignature(test.reason, test.reasonText)
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
		_, err := pgpKey.ArmorRevocationCertificate()
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
		t.Run(fmt.Sprintf("slugify(%s)", test.email), func(*testing.T) {
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
		panic(fmt.Sprintf("expected identities map to have 1 element, has %d", len(uids)))
	}

	return uids[0]
}

func TestGenerate(t *testing.T) {
	janeEmail := "jane@example.com"
	generatedKey, err := generateInsecure(janeEmail)

	if err != nil {
		t.Errorf("failed to generate PGP key in tests")
	}

	t.Run("generate makes a UID with just an email and no brackets", func(*testing.T) {
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

	t.Run("generate makes a key that by default expires in 60 days", func(*testing.T) {
		identityName := getSingleUid(generatedKey.Identities)
		sixtyDaysInSeconds := uint32((time.Hour * 24 * 60).Seconds())
		actualLifetimeOfKey := generatedKey.Identities[identityName].SelfSignature.KeyLifetimeSecs

		if *actualLifetimeOfKey != sixtyDaysInSeconds {
			t.Fatalf("expected KeyLifetimeSecs to be '%v', got '%v'", sixtyDaysInSeconds, *actualLifetimeOfKey)
		}

		for _, subkey := range generatedKey.Subkeys {
			actualLifetimeOfSubkey := subkey.Sig.SigLifetimeSecs
			if *actualLifetimeOfKey != sixtyDaysInSeconds {
				t.Fatalf("expected KeyLifetimeSecs of Subkey to be '%v', got '%v'", sixtyDaysInSeconds, *actualLifetimeOfSubkey)
			}
		}
	})
}

func TestLoadFromArmoredPublicKey(t *testing.T) {
	pgpKey, err := LoadFromArmoredPublicKey(examplePublicKey)
	if err != nil {
		t.Fatalf("LoadFromArmoredPublicKey(..) failed: %v", err)
	}
	expected := fingerprint.MustParse("0C10 C4A2 6E9B 1B46 E713  C8D2 BEBF 0628 DAFF 9F4B")
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
