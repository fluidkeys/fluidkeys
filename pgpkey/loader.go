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

// Loader provides a simple accessor method for loading private keys
type Loader struct {
}

// LoadFromArmoredEncryptedPrivateKey takes an asci armored private key and password, and passes
// it along to LoadFromArmoredEncryptedPrivateKey
func (f *Loader) LoadFromArmoredEncryptedPrivateKey(armoredKey string, password string) (*PgpKey, error) {
	return LoadFromArmoredEncryptedPrivateKey(armoredKey, password)
}
