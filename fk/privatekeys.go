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

package fk

import (
	"fmt"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

// loadPrivateKey exports a private key from GnuPG and returns it as a
// decrypted pgpkey.PgpKey
//
// Returns an IncorrectPassword error if either function call returns a bad
// password error
func loadPrivateKey(
	fingerprint fingerprint.Fingerprint,
	password string,
	gpg gpgwrapper.GnuPGInterface,
	loader pgpkey.LoaderInterface) (*pgpkey.PgpKey, error) {

	encryptedArmored, err := gpg.ExportPrivateKey(fingerprint, password)
	if err != nil {
		if _, ok := err.(*gpgwrapper.BadPasswordError); ok {
			return nil, &IncorrectPassword{
				message:       "gpg said the password was incorrect",
				originalError: err.Error(),
			}
		}
		return nil, fmt.Errorf("gpg export error: %v", err)
	}

	outKey, err := loader.LoadFromArmoredEncryptedPrivateKey(encryptedArmored, password)

	if err != nil {
		if _, ok := err.(*pgpkey.IncorrectPassword); ok {
			return nil, &IncorrectPassword{
				message:       "the password was incorrect",
				originalError: err.Error(),
			}
		}
		return nil, fmt.Errorf("failed to load key returned by GnuPG: %v", err)
	}

	return outKey, nil
}

// pushPrivateKeyBackToGpg takes a PgpKey with a decrypted PrivateKey and
// loads it back into GnuPG
func pushPrivateKeyBackToGpg(
	key pgpkey.PgpKeyInterface, password string, gpg gpgwrapper.GnuPGInterface) error {

	armoredPublicKey, err := key.Armor()
	if err != nil {
		return fmt.Errorf("failed to dump public key: %v", err)
	}

	armoredPrivateKey, err := key.ArmorPrivate(password)
	if err != nil {
		return fmt.Errorf("failed to dump private key: %v", err)
	}

	err = gpg.ImportArmoredKey(armoredPublicKey)
	if err != nil {
		return err
	}

	err = gpg.ImportArmoredKey(armoredPrivateKey)
	if err != nil {
		return err
	}

	return gpg.TrustUltimately(key.Fingerprint())
}
