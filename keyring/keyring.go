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

	"github.com/fluidkeys/fluidkeys/fingerprint"
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

type Keyring struct {
	realKeyring externalkeyring.Keyring
	backendType externalkeyring.BackendType
}

// SavePassword stores the given password in the keyring against the key and
// returns any error encountered in the underlying keyring.
func (k *Keyring) SavePassword(fp fingerprint.Fingerprint, password string) error {
	if k.noBackend() {
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
	if k.noBackend() {
		return "", false
	}

	if password, gotPassword = tryLoadFromPasswordFile(fp); gotPassword {
		return
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
	if k.noBackend() {
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

func makeKeyringKey(fp fingerprint.Fingerprint) string {
	return fmt.Sprintf("fluidkeys.pgpkey.%s", fp.Hex())
}

func makeKeyringLabel(fp fingerprint.Fingerprint) string {
	return fmt.Sprintf("Fluidkeys password for PGP key %s", fp.Hex())
}

const keyringServiceName string = "login"
