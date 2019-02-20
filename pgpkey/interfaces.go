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

package pgpkey

// LoadFromArmoredEncryptedPrivateKeyInterface provides and interface to the
// LoadFromArmoredEncryptedPrivateKey method
//
// LoadFromArmoredEncryptedPrivateKey takes an encrypted, asci armored
// private key and a password and returns a pointer to a PgpKey with:
//
// * a decrypted PrivateKey.
// * all subkeys decrypted
type LoadFromArmoredEncryptedPrivateKeyInterface interface {
	LoadFromArmoredEncryptedPrivateKey(string, string) (*PgpKey, error)
}

// ArmorInterface is the interface to the Armor and ArmorPrivate methods.
//
// Armor returns the public part of a key in armored format.
// ArmorPrivate returns the private part of a key in armored format.
type ArmorInterface interface {
	Armor() (string, error)
	ArmorPrivate(string) (string, error)
}
