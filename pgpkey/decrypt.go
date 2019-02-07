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
	"fmt"
	"io"
	"strings"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/crypto/openpgp/packet"
)

// DecryptArmored takes an ascii armored encrypted PGP message and attempts to decrypt it
// against the key, returning an io.Reader
func (p *PgpKey) DecryptArmored(encrypted string) (io.Reader, *packet.LiteralData, error) {
	err := p.ensureGotDecryptedPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	buffer := strings.NewReader(encrypted)
	block, err := armor.Decode(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding armor: %s", err)
	}

	var keyRing openpgp.EntityList = []*openpgp.Entity{&p.Entity}

	messageDetails, err := openpgp.ReadMessage(block.Body, keyRing, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading message: %s", err)
	}

	return messageDetails.UnverifiedBody, messageDetails.LiteralData, nil
}

// DecryptArmoredToString returns DecryptArmored as a string
func (p *PgpKey) DecryptArmoredToString(encrypted string) (string, *packet.LiteralData, error) {
	reader, literalData, err := p.DecryptArmored(encrypted)
	if err != nil {
		return "", nil, err
	}

	buffer := new(bytes.Buffer)
	if _, err = buffer.ReadFrom(reader); err != nil {
		return "", nil, err
	}
	return buffer.String(), literalData, nil
}
