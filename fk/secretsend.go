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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/fluidkeys/api"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/stringutils"
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
		secret, err = getSecretFromFile(filename, nil)

		printFileDivider(filename)
		out.Print(secret)
		printFileDivider("")
		out.Print("\n")

		out.Print(colour.Info("The file will be end-to-end encrypted to ") + recipientEmail + "\n")
		out.Print(colour.Info("so no-one else can read it 🕵️\n\n"))

		prompter := interactiveYesNoPrompter{}

		if !prompter.promptYesNo("Send "+filename+"?", "y", nil) {
			return 1
		}

		basename = filepath.Base(filename)
	} else {
		out.Print(colour.Info("Type or paste your message, ending by typing Ctrl-D\n"))
		out.Print(colour.Info("It will be end-to-end encrypted to ") + recipientEmail + "\n")
		out.Print(colour.Info("so no-one else can read it 🕵️\n\n"))

		secret, err = getSecretFromStdin(&stdinReader{})
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

	printSuccess("Sent. You should tell them to check Fluidkeys.\n")
	return 0
}

func getSecretFromFile(filename string, fileReader ioutilReadFileInterface) (string, error) {
	if fileReader == nil {
		fileReader = &ioutilReadFilePassthrough{}
	}

	secretData, err := fileReader.ReadFileMaxBytes(filename, secretMaxSizeBytes)

	if err == errTooMuchData {
		return "", fmt.Errorf("file is too large (max 10K)")
	} else if err != nil {
		return "", fmt.Errorf("error reading file: %v", err)
	}

	secret := string(secretData)
	if len(strings.TrimSpace(secret)) == 0 {
		return "", fmt.Errorf(filename + " is empty")
	}
	if !isValidTextSecret(secret) {
		return "", fmt.Errorf(filename + " contains disallowed characters")
	}

	return secret, nil
}

func getSecretFromStdin(scanner scanUntilEOFInterface) (string, error) {
	secret, err := scanner.scanUntilEOF()

	if err == errTooMuchData {
		return "", fmt.Errorf("input was too big (max 10K)")
	} else if err != nil {
		return "", err
	}

	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("empty message")
	}

	if !isValidTextSecret(secret) {
		return "", errors.New("Secret contains disallowed characters")
	}

	return secret, nil
}

func isValidTextSecret(text string) bool {
	return utf8.ValidString(text) && !stringutils.ContainsDisallowedRune(text)
}

type stdinReader struct{}

func (s *stdinReader) scanUntilEOF() (message string, err error) {
	output, err := readUpTo(os.Stdin, secretMaxSizeBytes)
	if err != nil {
		return "", err
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

type scanUntilEOFInterface interface {
	scanUntilEOF() (message string, err error)
}

type ioutilReadFileInterface interface {
	ReadFileMaxBytes(filename string, maxBytes int64) ([]byte, error)
}

type ioutilReadFilePassthrough struct {
}

func (r *ioutilReadFilePassthrough) ReadFileMaxBytes(filename string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	return readUpTo(f, maxBytes)
}

// readUpTo returns up to maxBytes from source, giving an error if
// source was longer than maxBytes
// there are three cases:
//
// 1. src < maxBytes  (OK, normal)
// 2. src == maxBytes (OK, unusual)
// 3. src > maxBytes  (not OK)
//
// in case 1) we expect to reach io.EOF
func readUpTo(source io.Reader, maxBytes int64) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	bytesRead, err := io.CopyN(buf, source, maxBytes+1)
	switch err {
	case io.EOF:
		// case 1 or 2
		// we should *always* hit io.EOF: the source should run out before maxBytes+1
		return buf.Bytes()[:bytesRead], nil

	case nil:
		// we didn't hit EOF, so CopyN must have reached maxBytes+1, ie there was too
		// much data
		return nil, errTooMuchData

	default:
		// some other error occurred
		return nil, err
	}
}

const secretMaxSizeBytes = 10 * 1024

var errTooMuchData error = errors.New("source had more data than maxBytes")
