package pgpkey

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/fluidkeys/crypto/openpgp"
)

func TestTheTestHelperFunctions(t *testing.T) {
	t.Run("load from ascii armored public key", func(*testing.T) {
		entity, err := readEntityFromString(examplePublicKey)
		if err != nil {
			t.Errorf("failed to load example PGP key: %v", err)
		}

		expectedUid := exampleUid

		_, ok := entity.Identities[expectedUid]

		if ok != true {
			t.Errorf("loaded exmaple PGP key, didn't have UID %s", expectedUid)
		}
	})
}

func TestSlugMethod(t *testing.T) {

	entity, err := readEntityFromString(examplePublicKey)
	if err != nil {
		t.Errorf("failed to load example PGP key: %v", err)
	}
	pgpKey := PgpKey{*entity}

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
		entity, err := readEntityFromString(examplePublicKey)
		if err != nil {
			t.Errorf("failed to load example PGP key: %v", err)
		}
		pgpKey := PgpKey{*entity}

		want := "test@example.com"
		got, err := pgpKey.Email()

		if err != nil {
			t.Fatalf("Error calling PgpKey.Email(): %v", err)
		}
		assertEqual(t, want, got)
	})
}

func TestFingerprintMethod(t *testing.T) {

	entity, err := readEntityFromString(examplePublicKey)
	if err != nil {
		t.Errorf("failed to load example PGP key: %v", err)
	}
	pgpKey := PgpKey{*entity}

	t.Run("test PgpKey.FingerprintString() returns the right string", func(*testing.T) {
		slug := pgpKey.FingerprintString()
		assertEqual(t, "0C10C4A26E9B1B46E713C8D2BEBF0628DAFF9F4B", slug)
	})
}

func TestFingerprintMethod(t *testing.T) {

	entity, err := readEntityFromString(examplePublicKey)
	if err != nil {
		t.Errorf("failed to load example PGP key: %v", err)
	}
	pgpKey := PgpKey{*entity}

	t.Run("test PgpKey.FingerprintString() returns the right string", func(*testing.T) {
		slug := pgpKey.FingerprintString()
		assertEqual(t, "8FBC076876F2B042AE2BA37B0BBD7E7E5B85C8D3", slug)
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

func readEntityFromString(asciiArmoredString string) (*openpgp.Entity, error) {
	ioReader := strings.NewReader(asciiArmoredString)
	entityList, err := openpgp.ReadArmoredKeyRing(ioReader)

	if err != nil {
		return nil, err
	}

	if len(entityList) != 1 {
		return nil, errors.New(fmt.Sprintf("expected 1 entity, got %d", len(entityList)))
	}
	return entityList[0], nil
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
		entity, err := readEntityFromString(armored)
		if err != nil {
			t.Errorf("failed to load example PGP key: %v", err)
		}
		expected := "<" + janeEmail + ">"
		actual := getSingleUid(entity.Identities)

		if expected != actual {
			t.Errorf("expected UID '%s', got '%s'", expected, actual)
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
