package keyring

import (
	"fmt"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	externalkeyring "github.com/fluidkeys/keyring"
)

// Load initialises the underlying keyring and returns a Keyring which provides
// accessor methods.
func Load() (*Keyring, error) {
	return load(externalkeyring.AvailableBackends())
}

func load(allowedBackends []externalkeyring.BackendType) (*Keyring, error) {
	ring, err := externalkeyring.Open(externalkeyring.Config{
		ServiceName:     keyringServiceName,
		AllowedBackends: allowedBackends,
	})

	if err != nil {
		return &Keyring{noBackend: true}, nil
	}

	return &Keyring{realKeyring: ring, noBackend: false}, nil
}

type Keyring struct {
	realKeyring externalkeyring.Keyring
	noBackend   bool // if true, all calls just return nothing
}

// SavePassword stores the given password in the keyring against the key and
// returns any error encountered in the underlying keyring.
func (k *Keyring) SavePassword(fp fingerprint.Fingerprint, password string) error {
	if k.noBackend {
		return nil
	}

	return k.realKeyring.Set(
		externalkeyring.Item{
			Key:   makeKeyringKey(fp),
			Label: makeKeyringLabel(fp),
			Data:  []byte(password),
		},
	)
}

// LoadPassword attempts to load a password from the keyring for the given key
// and returns (password, gotPassword).
func (k *Keyring) LoadPassword(fp fingerprint.Fingerprint) (password string, gotPassword bool) {
	if k.noBackend {
		return "", false
	}

	item, err := k.realKeyring.Get(makeKeyringKey(fp))
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
func (k *Keyring) PurgePassword(fp fingerprint.Fingerprint) error {
	if k.noBackend {
		return nil
	}

	err := k.realKeyring.Remove(makeKeyringKey(fp))
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

func makeKeyringKey(fp fingerprint.Fingerprint) string {
	return fmt.Sprintf("fluidkeys.pgpkey.%s", fp.Hex())
}

func makeKeyringLabel(fp fingerprint.Fingerprint) string {
	return fmt.Sprintf("Fluidkeys password for PGP key %s", fp.Hex())
}

const keyringServiceName string = "login"
