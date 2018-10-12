package keyring

import (
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	externalkeyring "github.com/fluidkeys/keyring"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Run("Load returns a keyring", func(t *testing.T) {
		keyring, err := Load()
		assert.ErrorIsNil(t, err)
		if keyring == nil {
			t.Fatalf("Load returned a nil Keyring")
		}
	})
}

func TestSavePassword(t *testing.T) {
	exampleKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	assert.ErrorIsNil(t, err)

	t.Run("save stores an item with sensible key, data and label", func(t *testing.T) {
		keyring := Keyring{realKeyring: externalkeyring.NewArrayKeyring(nil)}
		keyring.SavePassword(exampleKey, "password")

		item, err := keyring.realKeyring.Get(makeKeyringKey(exampleKey))
		assert.ErrorIsNil(t, err)

		assert.Equal(t, "fluidkeys.pgpkey.7C18DE4DE47813568B243AC8719BD63EF03BDC20", item.Key)
		assert.Equal(t, "Fluidkeys password for PGP key 7C18DE4DE47813568B243AC8719BD63EF03BDC20", item.Label)
		assert.Equal(t, []byte("password"), item.Data)
	})
}

func TestLoadPassword(t *testing.T) {
	exampleKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	assert.ErrorIsNil(t, err)

	t.Run("return ('', false) when no password is present", func(t *testing.T) {
		keyring := Keyring{realKeyring: externalkeyring.NewArrayKeyring(nil)}

		password, gotPassword := keyring.LoadPassword(exampleKey)
		assert.Equal(t, false, gotPassword)
		assert.Equal(t, "", password)
	})

	t.Run("return (password, true) when password is present", func(t *testing.T) {
		keyring := Keyring{realKeyring: externalkeyring.NewArrayKeyring(nil)}
		keyring.SavePassword(exampleKey, "foo")

		password, gotPassword := keyring.LoadPassword(exampleKey)
		assert.Equal(t, true, gotPassword)
		assert.Equal(t, "foo", password)
	})
}

func TestPurgePassword(t *testing.T) {
	exampleKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey3, "test3")
	assert.ErrorIsNil(t, err)

	t.Run("purge deletes a password", func(t *testing.T) {
		keyring := Keyring{realKeyring: externalkeyring.NewArrayKeyring(nil)}
		keyring.SavePassword(exampleKey, "foo")
		err := keyring.PurgePassword(exampleKey)

		assert.ErrorIsNil(t, err)

		keyringKeys, err := keyring.realKeyring.Keys()
		assert.ErrorIsNil(t, err)
		assert.Equal(t, 0, len(keyringKeys))
	})

	t.Run("purge returns nil error if no matching password for key", func(t *testing.T) {
		keyring := Keyring{realKeyring: externalkeyring.NewArrayKeyring(nil)}
		err := keyring.PurgePassword(exampleKey)

		assert.ErrorIsNil(t, err)
	})
}
