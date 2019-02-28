package keyring

import (
	"fmt"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	externalkeyring "github.com/fluidkeys/keyring"
	"os"
	"testing"
)

var exampleFingerprint = fingerprint.MustParse("AAAA1111AAAA1111AAAAAAAA1111AAAA1111AAAA")

func TestLoad(t *testing.T) {

	t.Run("Load returns a keyring", func(t *testing.T) {
		keyring, err := Load()
		assert.NoError(t, err)
		if keyring == nil {
			t.Fatalf("Load returned a nil Keyring")
		}
	})

	t.Run("if there are no underlying backends, load returns a dummy keyring", func(t *testing.T) {
		noBackends := []externalkeyring.BackendType{}
		keyring, err := load(noBackends)

		assert.NoError(t, err)
		if keyring == nil {
			t.Fatalf("Load returned a nil Keyring")
		}

		t.Run("dummy SavePassword returns nil error", func(t *testing.T) {
			err := keyring.SavePassword(exampleFingerprint, "foo")
			assert.NoError(t, err)
		})

		t.Run("dummy LoadPassword returns nil error", func(t *testing.T) {
			_, gotPassword := keyring.LoadPassword(exampleFingerprint)
			assert.Equal(t, false, gotPassword)
		})

		t.Run("dummy PurgePassword returns nil error", func(t *testing.T) {
			err := keyring.PurgePassword(exampleFingerprint)
			assert.NoError(t, err)
		})

	})
}

func TestSavePassword(t *testing.T) {
	t.Run("save stores an item with sensible key, data and label", func(t *testing.T) {
		keyring := makeTestKeyring()
		keyring.SavePassword(exampleFingerprint, "password")

		item, err := keyring.realKeyring.Get(makeKeyringKey(exampleFingerprint))
		assert.NoError(t, err)

		assert.Equal(t, "fluidkeys.pgpkey.AAAA1111AAAA1111AAAAAAAA1111AAAA1111AAAA", item.Key)
		assert.Equal(t, "Fluidkeys password for PGP key AAAA1111AAAA1111AAAAAAAA1111AAAA1111AAAA", item.Label)
		assert.Equal(t, []byte("password"), item.Data)
	})
}

func TestLoadPassword(t *testing.T) {
	t.Run("return ('', false) when no password is present", func(t *testing.T) {
		keyring := makeTestKeyring()

		password, gotPassword := keyring.LoadPassword(exampleFingerprint)
		assert.Equal(t, false, gotPassword)
		assert.Equal(t, "", password)
	})

	t.Run("return (password, true) when password is present", func(t *testing.T) {
		keyring := makeTestKeyring()
		keyring.SavePassword(exampleFingerprint, "foo")

		password, gotPassword := keyring.LoadPassword(exampleFingerprint)
		assert.Equal(t, true, gotPassword)
		assert.Equal(t, "foo", password)
	})
}

func TestPurgePassword(t *testing.T) {
	t.Run("purge deletes a password", func(t *testing.T) {
		keyring := makeTestKeyring()
		keyring.SavePassword(exampleFingerprint, "foo")
		err := keyring.PurgePassword(exampleFingerprint)

		assert.NoError(t, err)

		keyringKeys, err := keyring.realKeyring.Keys()
		assert.NoError(t, err)
		assert.Equal(t, 0, len(keyringKeys))
	})

	t.Run("purge returns nil error if no matching password for key", func(t *testing.T) {
		keyring := makeTestKeyring()
		err := keyring.PurgePassword(exampleFingerprint)

		assert.NoError(t, err)
	})
}

func TestName(t *testing.T) {
	var tests = []struct {
		backendType  externalkeyring.BackendType
		expectedName string
	}{
		{
			externalkeyring.SecretServiceBackend,
			"Linux login keyring",
		},
		{
			externalkeyring.KeychainBackend,
			"macOS Keychain",
		},
		{
			externalkeyring.InvalidBackend,
			"system keyring",
		},
		{
			"",
			"system keyring",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("for %s", test.backendType), func(t *testing.T) {
			keyring := Keyring{
				realKeyring: externalkeyring.NewArrayKeyring(nil),
				backendType: test.backendType,
			}

			assert.Equal(t, test.expectedName, keyring.Name())
		})

	}
}

func TestDiscoverDbusSessionBusAddress(t *testing.T) {
	dbusAddress := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	expectedDbusAddress := os.Getenv("EXPECTED_DBUS_SESSION_BUS_ADDRESS")

	if expectedDbusAddress != "" {
		// the caller script unset DBUS_SESSION_BUS_ADDRESS before
		// calling this test to simulate crontab.
		// We need to test whether godbus's init discovered and
		// set DBUS_SESSION_BUS_ADDRESS correctly.

		t.Run("DBUS_SESSION_BUS_ADDRESS should have been set to EXPECTED_DBUS_SESSION_BUS_ADDRESS", func(t *testing.T) {
			if dbusAddress != expectedDbusAddress {
				t.Fatalf("looks like we failed to discover DBUS_SESSION_BUS_ADDRESS correctly, expected: '%s', got: '%s'", expectedDbusAddress, dbusAddress)
			}
		})
	}
}

func makeTestKeyring() Keyring {
	const arrayKeyringForTesting externalkeyring.BackendType = "array-keyring-for-testing"

	return Keyring{
		realKeyring: externalkeyring.NewArrayKeyring(nil),
		backendType: arrayKeyringForTesting,
	}
}
