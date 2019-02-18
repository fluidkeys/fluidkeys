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

package gpgwrapper

import (
	"github.com/fluidkeys/fluidkeys/fingerprint"
)

// ExportPrivateKeyInterface is the interface that wraps the ExportPrivateKey
// method.
//
// ExportPrivateKey returns 1 ascii armored private key for the given
// fingerprint, assuming it is encrypted with the given password.
// The outputted private key is encrypted with the password.
type ExportPrivateKeyInterface interface {
	ExportPrivateKey(fpr fingerprint.Fingerprint, password string) (string, error)
}

// ImportArmoredKeyInterface is the interface that wraps the ExportPrivateKey
// ImportArmoredKey.
//
// ImportArmoredKey imports the given armored key into the GPG key ring
type ImportArmoredKeyInterface interface {
	ImportArmoredKey(string) error
}
