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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/fluidkeys/api"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func secretSend(recipientEmail string, filename string) exitCode {
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

	_, err = encryptSecret("dummy data to test encryption", "", pgpKey)
	if err != nil {
		printFailed("Couldn't encrypt to the key:")
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	var secret string
	var basename string
	if filename != "" {
		secret, err = getSecretFromFile(filename)
		basename = filepath.Base(filename)
	} else {
		secret, err = getSecretFromStdin()
		basename = ""
	}
	if err != nil {
		printFailed("Error: " + err.Error())
		return 1
	}

	encryptedSecret, err := encryptSecret(secret, basename, pgpKey)
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

func getSecretFromFile(filename string) (string, error) {
	secretData, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("error reading file: " + err.Error())
	}
	secret := string(secretData)
	if len(strings.TrimSpace(secret)) == 0 {
		return "", fmt.Errorf(filename + " is empty")
	}
	out.Print("---\n")
	out.Print(secret)
	out.Print("---\n\n")

	prompter := interactiveYesNoPrompter{}

	if !prompter.promptYesNo("Send "+filename+"?", "y", nil) {
		return "", errors.New("didn't accept prompt to send file")
	}

	return secret, nil
}

func getSecretFromStdin() (string, error) {
	out.Print("\n")
	out.Print(colour.Info(femaleSpyEmoji + "  Type or paste your message, ending by typing Ctrl-D\n"))
	out.Print(colour.Info("   It will be end-to-end encrypted so no-one else can read it\n\n"))

	secret, err := scanUntilEOF()
	if err != nil {
		log.Panic(err)
		return "", err
	}

	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("empty message")
	}

	return secret, nil
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

func encryptSecret(secret string, filename string, pgpKey *pgpkey.PgpKey) (string, error) {
	buffer := bytes.NewBuffer(nil)
	message, err := armor.Encode(buffer, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}

	pgpWriteCloser, err := openpgp.Encrypt(
		message,
		[]*openpgp.Entity{&pgpKey.Entity},
		nil,
		makeFileHintsForFilename(filename),
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

func makeFileHintsForFilename(filename string) *openpgp.FileHints {
	fileHints := openpgp.FileHints{
		IsBinary: false,
		// We don't set ModTime, let it be the time the receiver saves it
	}
	if filename == "" {
		fileHints.FileName = "_CONSOLE"
		// This signifies that the contents should not be written to disk
		// See: https://tools.ietf.org/html/rfc4880#section-5.9
	} else {
		fileHints.FileName = filename
	}
	return &fileHints
}

const femaleSpyEmoji = "\xf0\x9f\x95\xb5\xef\xb8\x8f\xe2\x80\x8d\xe2\x99\x80\xef\xb8\x8f"

// containsDisallowedRune checks whether the given input string contains a disallowed rune
func containsDisallowedRune(input string) bool {
	for _, r := range input {
		switch {
		case 0 <= r && r <= 9:
			return true
		case 11 <= r && r <= 12:
			return true
		case r == '\n': // 10
			continue
		case r == '\r': // 13
			continue
		case 14 <= r && r <= 31:
			return true
		case r == 127: // DEL
			return true
		default:
			continue
		}
	}
	return false
}
