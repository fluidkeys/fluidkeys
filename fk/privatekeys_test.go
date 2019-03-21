package fk

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

type mockKey struct {
	armorString string
	armorError  error

	armorPrivateString string
	armorPrivateError  error

	fingerprint fpr.Fingerprint
}

func (m *mockKey) Armor() (string, error) {
	return m.armorString, m.armorError
}

func (m *mockKey) ArmorPrivate(password string) (string, error) {
	return m.armorPrivateString, m.armorPrivateError
}

func (m *mockKey) Fingerprint() fpr.Fingerprint {
	return m.fingerprint
}

type mockGpg struct {
	exportPrivateKeyString string
	exportPrivateKeyError  error

	importArmoredKeyError error

	trustUltimatelyCapturedFingerprint fpr.Fingerprint
	trustUltimatelyError               error
}

func (m *mockGpg) ExportPrivateKey(fingerprint fpr.Fingerprint, password string) (string, error) {
	return m.exportPrivateKeyString, m.exportPrivateKeyError
}

func (m *mockGpg) ImportArmoredKey(armoredKey string) error {
	return m.importArmoredKeyError
}

func (m *mockGpg) TrustUltimately(fingerprint fpr.Fingerprint) error {
	m.trustUltimatelyCapturedFingerprint = fingerprint
	return m.trustUltimatelyError
}

type mockLoadPrivateKey struct {
	returnKey   *pgpkey.PgpKey
	returnError error
}

func (m *mockLoadPrivateKey) LoadFromArmoredEncryptedPrivateKey(string, string) (*pgpkey.PgpKey, error) {
	return m.returnKey, m.returnError
}

func TestLoadPrivateKey(t *testing.T) {
	key, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey2, "test2")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("with ExportPrivateKey returning a key and the password is correct", func(t *testing.T) {
		gpg := mockGpg{
			exportPrivateKeyString: exampledata.ExamplePrivateKey2,
			exportPrivateKeyError:  nil,
		}

		mockLoader := mockLoadPrivateKey{
			returnKey:   key,
			returnError: nil,
		}

		key, err := loadPrivateKey(exampledata.ExampleFingerprint2, "test2", &gpg, &mockLoader)

		t.Run("doesn't get an error", func(t *testing.T) {
			assert.NoError(t, err)
		})

		t.Run("key is not nil", func(t *testing.T) {
			if key == nil {
				t.Fatalf("expected PgpKey, got nil")
			}
		})

		t.Run("key has PrivateKey", func(t *testing.T) {
			if key.PrivateKey == nil {
				t.Fatalf("expected PgpKey.PrivateKey, got nil")
			}
		})

		t.Run("key PrivateKey is decrypted", func(t *testing.T) {
			if key.PrivateKey.Encrypted {
				t.Fatalf("expected PgpKey.PrivateKey.Encrypted=false, got true")
			}
		})

		for i, subkey := range key.Subkeys {
			t.Run(fmt.Sprintf("key.Subkey[%d] has PrivateKey", i), func(t *testing.T) {
				if subkey.PrivateKey == nil {
					t.Fatalf("expected subkey.PrivateKey, got nil")
				}
			})

			t.Run(fmt.Sprintf("key.Subkey[%d] PrivateKey is decrypted", i), func(t *testing.T) {
				if subkey.PrivateKey.Encrypted {
					t.Fatalf("expected subkey.PrivateKey.Encrypted=false, got true")
				}
			})
		}
	})

	t.Run("returns IncorrectPassword if ExportPrivateKey returns a bad password error", func(t *testing.T) {
		gpg := mockGpg{
			exportPrivateKeyString: exampledata.ExamplePrivateKey2,
			exportPrivateKeyError:  &gpgwrapper.BadPasswordError{},
		}
		mockLoader := mockLoadPrivateKey{
			returnKey:   nil,
			returnError: &pgpkey.IncorrectPassword{},
		}

		_, err := loadPrivateKey(exampledata.ExampleFingerprint2, "[irrelevant for tests]", &gpg, &mockLoader)

		incorrectPasswordError, ok := err.(*IncorrectPassword)
		if !ok {
			t.Fatalf("expected `IncorrectPasswordError`, got %v", err)
		}

		expectedString := "gpg said the password was incorrect"
		gotString := incorrectPasswordError.Error()
		if expectedString != gotString {
			t.Fatalf("expected error string '%s', got '%s'", expectedString, gotString)
		}
	})

	t.Run("returns IncorrectPassword if LoadFromArmoredEncryptedPrivateKey returns a bad password error", func(t *testing.T) {
		gpg := mockGpg{
			exportPrivateKeyString: exampledata.ExamplePrivateKey2,
			exportPrivateKeyError:  nil,
		}
		mockLoader := mockLoadPrivateKey{
			returnKey:   nil,
			returnError: &pgpkey.IncorrectPassword{},
		}

		_, err := loadPrivateKey(exampledata.ExampleFingerprint2, "[irrelevant for tests]", &gpg, &mockLoader)

		incorrectPasswordError, ok := err.(*IncorrectPassword)
		if !ok {
			t.Fatalf("expected `IncorrectPasswordError`, got %v", err)
		}

		expectedString := "the password was incorrect"
		gotString := incorrectPasswordError.Error()
		if expectedString != gotString {
			t.Fatalf("expected error string '%s', got '%s'", expectedString, gotString)
		}
	})

	t.Run("returns an error if ExportPrivateKey returns some other GnuPG error", func(t *testing.T) {
		gpg := mockGpg{
			exportPrivateKeyString: "",
			exportPrivateKeyError:  fmt.Errorf("some error"),
		}
		mockLoader := mockLoadPrivateKey{
			returnKey:   key,
			returnError: nil,
		}

		_, err := loadPrivateKey(exampledata.ExampleFingerprint2, "irrelevant for this test", &gpg, &mockLoader)

		t.Run("returns an error", func(t *testing.T) {
			assert.GotError(t, err)
		})
	})

	t.Run("returns an error if pgpkey.LoadFromArmoredEncryptedPrivateKey returns an error", func(t *testing.T) {
		gpg := mockGpg{
			exportPrivateKeyString: exampledata.ExamplePrivateKey2,
			exportPrivateKeyError:  nil,
		}

		mockLoader := mockLoadPrivateKey{
			returnKey:   nil,
			returnError: fmt.Errorf("some error"),
		}

		_, err := loadPrivateKey(exampledata.ExampleFingerprint2, "irrelevant", &gpg, &mockLoader)
		assert.GotError(t, err)
	})
}

func TestPushPrivateKeyBackToGpg(t *testing.T) {
	key, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey2, "test2")
	assert.NoError(t, err)

	t.Run("returns error=nil if everything works", func(t *testing.T) {
		gpg := mockGpg{
			importArmoredKeyError: nil,
		}

		err := pushPrivateKeyBackToGpg(key, "test2", &gpg)
		assert.NoError(t, err)

		// check we made it through to the end
		assert.Equal(t, key.Fingerprint(), gpg.trustUltimatelyCapturedFingerprint)
	})

	t.Run("returns an error if key.Armor() returns an error", func(t *testing.T) {
		key := mockKey{
			armorString:        "",
			armorError:         fmt.Errorf("some error in Armor()"),
			armorPrivateString: "",
			armorPrivateError:  nil,
		}

		gpg := mockGpg{
			importArmoredKeyError: nil,
		}
		err := pushPrivateKeyBackToGpg(&key, "[irrelevant]", &gpg)
		assert.GotError(t, err)
	})

	t.Run("returns an error if key.ArmorPrivate() returns an error", func(t *testing.T) {
		gpg := mockGpg{
			importArmoredKeyError: nil,
		}

		key := mockKey{
			armorPrivateError: fmt.Errorf("some error in ArmorPrivate()"),
		}
		err := pushPrivateKeyBackToGpg(&key, "wrong-password", &gpg)
		assert.GotError(t, err)
	})

	t.Run("returns an error if ImportedArmoredKey() returns an error", func(t *testing.T) {
		gpg := mockGpg{
			importArmoredKeyError: fmt.Errorf("some error in ImportedArmoredKey"),
		}
		err := pushPrivateKeyBackToGpg(key, "test2", &gpg)
		assert.GotError(t, err)
	})

	t.Run("returns an error if TrustUltimately returns an error", func(t *testing.T) {
		gpg := mockGpg{
			trustUltimatelyError: fmt.Errorf("some error in TrustUltimately"),
		}
		err := pushPrivateKeyBackToGpg(key, "test2", &gpg)
		assert.GotError(t, err)
	})
}
