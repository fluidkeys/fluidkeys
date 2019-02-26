// Copyright 2019 Paul Furley and Ian Drysdale
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

import (
	"bytes"

	"github.com/fluidkeys/crypto/openpgp"
)

func (p *PgpKey) MakeArmoredDetachedSignature(dataToSign []byte) (string, error) {
	err := p.ensureGotDecryptedPrivateKey()
	if err != nil {
		return "", err
	}

	outputBuf := bytes.NewBuffer(nil)
	entity := p.Entity

	err = openpgp.ArmoredDetachSign(outputBuf, &entity, bytes.NewReader(dataToSign), nil)
	if err != nil {
		return "", err
	}
	return outputBuf.String(), nil
}
