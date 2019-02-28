// Copyright 2018 Paul Furley and Ian Drysdale
//
// This file is part of Fluidkeys Client which makes it simple to use OpenPGP.
//
// Fluidkeys Client is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Fluidkeys Client is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Fluidkeys Client.  If not, see <https://www.gnu.org/licenses/>.

package keyring

import (
	"fmt"
	"log"

	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	externalkeyring "github.com/fluidkeys/keyring"
)

// Load initialises the underlying keyring and returns a Keyring which provides
// accessor methods.
func Load() (*Keyring, error) {
	return load(externalkeyring.AvailableBackends())
}

func load(allowedBackends []externalkeyring.BackendType) (*Keyring, error) {
	ring, backendType, err := externalkeyring.Open(externalkeyring.Config{
		ServiceName:     keyringServiceName,
		AllowedBackends: allowedBackends,
		KeychainName:    "login",
	})

	if err != nil && backendType == externalkeyring.InvalidBackend {
		// Return a valid, but "dummy" Keyring which just returns
		// (without an error) on LoadPassword, SavePassword etc
		log.Printf("failed to load keyring backend: %v", err)
		return &Keyring{}, nil
	}

	return &Keyring{
		realKeyring: ring,
		backendType: backendType,
	}, nil
}

// Keyring provides accessor methods for the user's system's keyring.
type Keyring struct {
	realKeyring externalkeyring.Keyring
	backendType externalkeyring.BackendType
}

// SavePassword stores the given password in the keyring against the key and
// returns any error encountered in the underlying keyring.
func (k *Keyring) SavePassword(fingerprint fpr.Fingerprint, newPassword string) error {
	if k.noBackend() {
		return nil
	}

	shouldStorePassword := false

	currentPassword, got := k.LoadPassword(fingerprint)

	if !got {
		log.Printf("SavePassword: keyring has no password saved for %s, saving now",
			fingerprint.Hex())
		shouldStorePassword = true
	} else if currentPassword != newPassword {
		log.Printf("SavePassword: updating existing password in keyring for %s", fingerprint.Hex())
		shouldStorePassword = true
	}

	if shouldStorePassword {
		return k.realKeyring.Set(
			externalkeyring.Item{
				Key:   makeKeyringKey(fingerprint),
				Label: makeKeyringLabel(fingerprint),
				Data:  []byte(newPassword),
			},
		)
	} else {
		return nil // nothing to do
	}
}

// LoadPassword attempts to load a password from the keyring for the given key
// and returns (password, gotPassword).
func (k *Keyring) LoadPassword(fingerprint fpr.Fingerprint) (password string, gotPassword bool) {
	if k.noBackend() {
		return "", false
	}

	item, err := k.realKeyring.Get(makeKeyringKey(fingerprint))
	if err != nil {
		if isNotFoundError(err) {
			log.Printf("keyring returned isNotFoundError for %s: %v", fingerprint.Hex(), err)
			return "", false
		} else {
			log.Printf("unexpected error getting password from keyring: %v", err)
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
func (k *Keyring) PurgePassword(fingerprint fpr.Fingerprint) error {
	if k.noBackend() {
		return nil
	}

	err := k.realKeyring.Remove(makeKeyringKey(fingerprint))
	if err != nil && !isNotFoundError(err) {
		// ignore the is-not-found error since it means the password
		// is already purged
		return err
	}
	return nil
}

func (k *Keyring) Name() string {
	switch k.backendType {
	case externalkeyring.SecretServiceBackend:
		return "Linux login keyring"

	case externalkeyring.KeychainBackend:
		return "macOS Keychain"

	default:
		return "system keyring"
	}
}

func (k *Keyring) noBackend() bool {
	return k.backendType == "" || k.backendType == externalkeyring.InvalidBackend
}

func isNotFoundError(err error) bool {
	return err == externalkeyring.ErrKeyNotFound
}

func makeKeyringKey(fingerprint fpr.Fingerprint) string {
	return fmt.Sprintf("fluidkeys.pgpkey.%s", fingerprint.Hex())
}

func makeKeyringLabel(fingerprint fpr.Fingerprint) string {
	return fmt.Sprintf("Fluidkeys password for PGP key %s", fingerprint.Hex())
}

const keyringServiceName string = "login"
