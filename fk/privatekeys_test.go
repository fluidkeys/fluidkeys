package fk

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

type mockExportPrivateKey struct {
	returnString string
	returnError  error
}

func (m *mockExportPrivateKey) ExportPrivateKey(fingerprint fingerprint.Fingerprint, password string) (string, error) {
	return m.returnString, m.returnError
}

type mockImportArmoredKey struct {
	returnError error
}

func (m *mockImportArmoredKey) ImportArmoredKey(armoredKey string) error {
	return m.returnError
}

type mockLoadFromArmoredEncryptedPrivateKey struct {
	returnKey   *pgpkey.PgpKey
	returnError error
}

func (m mockLoadFromArmoredEncryptedPrivateKey) LoadFromArmoredEncryptedPrivateKey(string, string) (*pgpkey.PgpKey, error) {
	return m.returnKey, m.returnError
}

type mockArmor struct {
	armorReturnString        string
	armorReturnError         error
	armorPrivateReturnString string
	armorPrivateReturnError  error
}

func (m *mockArmor) Armor() (string, error) {
	return m.armorReturnString, m.armorReturnError
}

func (m *mockArmor) ArmorPrivate(password string) (string, error) {
	return m.armorPrivateReturnString, m.armorPrivateReturnError
}

func TestLoadPrivateKey(t *testing.T) {
	key, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey2, "test2")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("with ExportPrivateKey returning a key and the password is correct", func(t *testing.T) {
		mockGpg := mockExportPrivateKey{
			returnString: exampledata.ExamplePrivateKey2,
			returnError:  nil,
		}

		mockLoader := mockLoadFromArmoredEncryptedPrivateKey{
			returnKey:   key,
			returnError: nil,
		}

		key, err := loadPrivateKey(exampledata.ExampleFingerprint2, "test2", &mockGpg, &mockLoader)

		t.Run("doesn't get an error", func(t *testing.T) {
			assert.ErrorIsNil(t, err)
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
		mockGpg := mockExportPrivateKey{
			returnString: exampledata.ExamplePrivateKey2,
			returnError:  &gpgwrapper.BadPasswordError{},
		}
		mockLoader := mockLoadFromArmoredEncryptedPrivateKey{
			returnKey:   nil,
			returnError: &pgpkey.IncorrectPassword{},
		}

		_, err := loadPrivateKey(exampledata.ExampleFingerprint2, "[irrelevant for tests]", &mockGpg, &mockLoader)

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
		mockGpg := mockExportPrivateKey{
			returnString: exampledata.ExamplePrivateKey2,
			returnError:  nil,
		}
		mockLoader := mockLoadFromArmoredEncryptedPrivateKey{
			returnKey:   nil,
			returnError: &pgpkey.IncorrectPassword{},
		}

		_, err := loadPrivateKey(exampledata.ExampleFingerprint2, "[irrelevant for tests]", &mockGpg, &mockLoader)

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
		mockGpg := mockExportPrivateKey{
			returnString: "",
			returnError:  fmt.Errorf("some error"),
		}
		mockLoader := mockLoadFromArmoredEncryptedPrivateKey{
			returnKey:   key,
			returnError: nil,
		}

		_, err := loadPrivateKey(exampledata.ExampleFingerprint2, "irrelevant for this test", &mockGpg, &mockLoader)

		t.Run("returns an error", func(t *testing.T) {
			assert.ErrorIsNotNil(t, err)
		})
	})

	t.Run("returns an error if pgpkey.LoadFromArmoredEncryptedPrivateKey returns an error", func(t *testing.T) {
		mockGpg := mockExportPrivateKey{
			returnString: exampledata.ExamplePrivateKey2,
			returnError:  nil,
		}

		mockLoader := mockLoadFromArmoredEncryptedPrivateKey{
			returnKey:   nil,
			returnError: fmt.Errorf("some error"),
		}

		_, err := loadPrivateKey(exampledata.ExampleFingerprint2, "irrelevant", &mockGpg, &mockLoader)
		assert.ErrorIsNotNil(t, err)
	})
}

func TestPushPrivateKeyBackToGpg(t *testing.T) {
	// key, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey2, "test2")
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// fingerprint := exampledata.ExampleFingerprint2

	t.Run("returns error=nil if everything works", func(t *testing.T) {
		mockKey := mockArmor{
			armorReturnString:        "",
			armorReturnError:         nil,
			armorPrivateReturnString: "",
			armorPrivateReturnError:  nil,
		}

		mockImporter := mockImportArmoredKey{
			returnError: nil,
		}

		err := pushPrivateKeyBackToGpg(&mockKey, "[irrelevant]", &mockImporter)
		assert.ErrorIsNil(t, err)
	})

	t.Run("returns an error if key.Armor() returns an error", func(t *testing.T) {
		mockKey := mockArmor{
			armorReturnString:        "",
			armorReturnError:         fmt.Errorf("some error in Armor()"),
			armorPrivateReturnString: "",
			armorPrivateReturnError:  nil,
		}

		mockImporter := mockImportArmoredKey{
			returnError: nil,
		}
		err := pushPrivateKeyBackToGpg(&mockKey, "[irrelevant]", &mockImporter)
		assert.ErrorIsNotNil(t, err)
	})

	t.Run("returns an error if key.ArmorPrivate() returns an error", func(t *testing.T) {
		mockKey := mockArmor{
			armorReturnString:        "",
			armorReturnError:         nil,
			armorPrivateReturnString: "",
			armorPrivateReturnError:  fmt.Errorf("some error in ArmorPrivate()"),
		}

		mockImporter := mockImportArmoredKey{
			returnError: nil,
		}
		err := pushPrivateKeyBackToGpg(&mockKey, "[irrelevant]", &mockImporter)
		assert.ErrorIsNotNil(t, err)
	})

	t.Run("returns an error if ImportedArmoredKey() returns an error", func(t *testing.T) {
		mockKey := mockArmor{
			armorReturnString:        "",
			armorReturnError:         nil,
			armorPrivateReturnString: "",
			armorPrivateReturnError:  nil,
		}

		mockImporter := mockImportArmoredKey{
			returnError: fmt.Errorf("some error in ImportedArmoredKey"),
		}
		err := pushPrivateKeyBackToGpg(&mockKey, "[irrelevant]", &mockImporter)
		assert.ErrorIsNotNil(t, err)
	})
}
