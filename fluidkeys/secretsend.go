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

package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"strings"

	"github.com/fluidkeys/fluidkeys/colour"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func secretSend(recipientEmail string) exitCode {
	armoredPublicKey, err := client.GetPublicKey(recipientEmail)
	if err != nil {
		printFailed("Couldn't get the public key for " + recipientEmail + "\n")
		return 1
	}

	printSuccess("Found public key for " + recipientEmail + "\n")

	pgpKey, err := pgpkey.LoadFromArmoredPublicKey(armoredPublicKey)
	if err != nil {
		printFailed("Couldn't load the public key:")
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	_, err = encryptSecret("dummy data to test encryption", pgpKey)
	if err != nil {
		printFailed("Couldn't encrypt to the key:")
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	out.Print("\n")
	out.Print("[type or paste your message, ending by typing Ctrl-D]\n\n")

	secret, err := scanUntilEOF()
	if err != nil {
		panic(err)
		return 1
	}

	if strings.TrimSpace(secret) == "" {
		printFailed("Exiting due to empty message.\n")
		return 1
	}

	encryptedSecret, err := encryptSecret(secret, pgpKey)
	if err != nil {
		printFailed("Couldn't encrypt the secret:")
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	err = client.CreateSecret(pgpKey.Fingerprint(), encryptedSecret)
	if err != nil {
		printFailed("Couldn't send the secret to " + recipientEmail)
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	printSuccess("Successfully sent secret to " + recipientEmail + "\n")

	out.Print("Tell them to get it by running\n")
	out.Print("  " + colour.CommandLineCode("fk secret receive\n\n"))
	return 0
}

func scanUntilEOF() (message string, err error) {
	reader := bufio.NewReader(os.Stdin)
	var output []rune

	for {
		input, _, err := reader.ReadRune()
		if err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}
		output = append(output, input)
	}

	return string(output), nil
}

func encryptSecret(secret string, pgpKey *pgpkey.PgpKey) (string, error) {
	buffer := bytes.NewBuffer(nil)
	message, err := armor.Encode(buffer, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}

	pgpWriteCloser, err := openpgp.Encrypt(
		message,
		[]*openpgp.Entity{&pgpKey.Entity},
		nil,
		nil,
		nil,
	)
	if err != nil {
		return "", err
	}

	_, err = pgpWriteCloser.Write([]byte(secret))
	if err != nil {
		return "", err
	}

	pgpWriteCloser.Close()
	message.Close()
	return buffer.String(), nil
}
