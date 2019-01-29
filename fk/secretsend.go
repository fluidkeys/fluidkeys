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
	"bufio"
	"bytes"
	"io"
	"log"
	"os"
	"strings"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/fluidkeys/api"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func secretSend(recipientEmail string) exitCode {
	armoredPublicKey, err := client.GetPublicKey(recipientEmail)
	if err != nil {
		if err == api.ErrPublicKeyNotFound {
			out.Print("\n")
			out.Print("Couldn't find " + recipientEmail + " on Fluidkeys.\n\n")
			out.Print("You can invite them to install Fluidkeys:\n")
			out.Print("───\n")
			out.Print(colour.Warning(`I'd like to send you an encrypted secret with Fluidkeys.

You can download and set up Fluidkeys here:

https://download.fluidkeys.com#` + recipientEmail + `
`))
			out.Print("───\n")
			return 1
		}
		printFailed("Failed to get the public key for " + recipientEmail + "\n")
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	printSuccess("Found public key for " + recipientEmail)

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
	out.Print(colour.Info(femaleSpyEmoji + "  Type or paste your message, ending by typing Ctrl-D\n"))
	out.Print(colour.Info("   It will be end-to-end encrypted so no-one else can read it\n\n"))

	secret, err := scanUntilEOF()
	if err != nil {
		log.Panic(err)
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

const femaleSpyEmoji = "\xf0\x9f\x95\xb5\xef\xb8\x8f\xe2\x80\x8d\xe2\x99\x80\xef\xb8\x8f"
