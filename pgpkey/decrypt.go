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
	"unicode/utf8"

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

// DecryptArmoredToString returns DecryptArmored as a UTF8 string. If the decrypted data does not
// decode as UTF-8, it will return an error.
func (p *PgpKey) DecryptArmoredToString(encrypted string) (string, *packet.LiteralData, error) {
	reader, literalData, err := p.DecryptArmored(encrypted)
	if err != nil {
		return "", nil, err
	}
	if literalData.IsBinary {
		return "", nil, fmt.Errorf("got binary data, expected text")
	}

	buffer := new(bytes.Buffer)
	if _, err = buffer.ReadFrom(reader); err != nil {
		return "", nil, err
	}

	text := buffer.String()
	if !utf8.ValidString(text) {
		return "", nil, fmt.Errorf("decrypted data was not valid UTF-8")
	}
	return text, literalData, nil
}
