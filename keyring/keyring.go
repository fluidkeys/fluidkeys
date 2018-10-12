package keyring

import (
	"fmt"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	externalkeyring "github.com/fluidkeys/keyring"
)

// Load initialises the underlying keyring and returns a Keyring which provides
// accessor methods.
func Load() (*Keyring, error) {
	ring, err := externalkeyring.Open(externalkeyring.Config{
		ServiceName: keyringServiceName,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to open keyring: %v", err)
	}

	keyring := Keyring{
		realKeyring: ring,
	}

	return &keyring, nil
}

type Keyring struct {
	realKeyring externalkeyring.Keyring
}

// SavePassword stores the given password in the keyring against the key and
// returns any error encountered in the underlying keyring.
func (k *Keyring) SavePassword(key *pgpkey.PgpKey, password string) error {
	return k.realKeyring.Set(
		externalkeyring.Item{
			Key:   makeKeyringKey(key),
			Label: makeKeyringLabel(key),
			Data:  []byte(password),
		},
	)
}

// LoadPassword attempts to load a password from the keyring for the given key
// and returns (password, gotPassword).
func (k *Keyring) LoadPassword(key *pgpkey.PgpKey) (password string, gotPassword bool) {
	item, err := k.realKeyring.Get(makeKeyringKey(key))
	if err != nil {
		if isNotFoundError(err) {
			return "", false
		} else {
			// TODO: log that an unexpected error was encountered
		}

	}
	password = string(item.Data)
	gotPassword = true
	return
}

// PurgePassword deletes the key from the keyring or returns an error if it
// encounters one with the underlying keyring.
// If the keyring announces the key wasn't found, PurgePassword swallows
// that particular error.
func (k *Keyring) PurgePassword(key *pgpkey.PgpKey) error {
	err := k.realKeyring.Remove(makeKeyringKey(key))
	if err != nil && !isNotFoundError(err) {
		// ignore the is-not-found error since it means the password
		// is already purged
		return err
	}
	return nil
}

func isNotFoundError(err error) bool {
	return err == externalkeyring.ErrKeyNotFound
}

func makeKeyringKey(key *pgpkey.PgpKey) string {
	return fmt.Sprintf("fluidkeys.pgpkey.%s", key.Fingerprint().Hex())
}

func makeKeyringLabel(key *pgpkey.PgpKey) string {
	return fmt.Sprintf("Fluidkeys password for PGP key %s", key.Fingerprint().Hex())
}

const keyringServiceName string = "login"
