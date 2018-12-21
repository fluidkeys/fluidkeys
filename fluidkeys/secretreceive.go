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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"

	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
)

func secretReceive() exitCode {
	out.Print("\n")
	keys, err := loadPgpKeys()
	var downloadedSecrets []secret

	if err != nil {
		printFailed("Couldn't load PGP keys")
		return 1
	}

	out.Print(colour.Info("Downloading secrets...") + "\n\n")

	sawError := false

	for _, key := range keys {
		if !Config.ShouldPublishToAPI(key.Fingerprint()) {
			message := "Not published in Fluidkeys directory"
			out.Print("⛔ " + displayName(&key) + ": " + colour.Warning(message) + "\n")
			continue
		}
		secrets, secretErrors, err := downloadAndDecryptSecrets(key)
		if err != nil {
			switch err.(type) {
			case errNoSecretsFound:
				out.Print("📭 " + displayName(&key) + ": No secrets found\n")
			case errDecryptPrivateKey:
				message := fmt.Sprintf("Error getting private key and password: %s", err)
				out.Print("📪 " + displayName(&key) + ": " + colour.Failure(message) + "\n")
			case errListSecrets:
				out.Print("📪 " + displayName(&key) + ": " + colour.Failure(err.Error()) + "\n")
			default:
				out.Print("📪 " + displayName(&key) + ": " + colour.Failure(err.Error()) + "\n")
			}
			continue
		}
		out.Print("📬 " + displayName(&key) + ":\n")

		for i, secret := range secrets {
			out.Print(formatSecretListItem(i+1, secret.decryptedContent))
		}
		downloadedSecrets = append(downloadedSecrets, secrets...)

		out.Print(strings.Repeat(secretDividerRune, secretDividerLength) + "\n")

		if len(secretErrors) > 0 {
			output := humanize.Pluralize(len(secretErrors), "secret", "secrets") + " failed to download for " + displayName(&key) + ":\n"
			out.Print(colour.Failure(colour.StripAllColourCodes(output)))
			for _, error := range secretErrors {
				printFailed(error.Error())
			}
			sawError = true
		}
	}

	if len(downloadedSecrets) > 0 {
		prompter := interactiveYesNoPrompter{}
		out.Print("\n")
		if prompter.promptYesNo("Delete now?", "Y", nil) == true {
			for _, secret := range downloadedSecrets {
				err := client.DeleteSecret(*secret.sentToFingerprint, secret.UUID.String())
				if err != nil {
					log.Printf("failed to delete secret '%s': %v", secret.UUID, err)
				}
			}
		}
	}

	if sawError {
		return 1
	}
	return 0
}

func downloadAndDecryptSecrets(key pgpkey.PgpKey) (secrets []secret, secretErrors []error, err error) {
	encryptedSecrets, err := client.ListSecrets(key.Fingerprint())
	if err != nil {
		return nil, nil, errListSecrets{originalError: err}
	}
	if len(encryptedSecrets) == 0 {
		return nil, nil, errNoSecretsFound{}
	}
	privateKey, _, err := getDecryptedPrivateKeyAndPassword(&key, &interactivePasswordPrompter{})
	if err != nil {
		return nil, nil, errDecryptPrivateKey{originalError: err}
	}
	for _, encryptedSecret := range encryptedSecrets {
		secret, err := decryptAPISecret(encryptedSecret, privateKey)
		if err != nil {
			secretErrors = append(secretErrors, err)
		} else {
			secrets = append(secrets, *secret)
		}
	}
	return secrets, secretErrors, nil
}

func formatSecretListItem(listNumber int, decryptedContent string) (output string) {
	displayCounter := fmt.Sprintf(out.NoLogCharacter+" %d. ", listNumber)
	trimmedDivider := strings.Repeat(secretDividerRune, secretDividerLength-(1+len([]rune(displayCounter))))
	output = displayCounter + trimmedDivider + "\n"
	output = output + decryptedContent
	if !strings.HasSuffix(decryptedContent, "\n") {
		output = output + "\n"
	}
	return output
}

func decryptAPISecret(encryptedSecret v1structs.Secret, pgpKey *pgpkey.PgpKey) (*secret, error) {
	decryptedContent, err := decrypt(encryptedSecret.EncryptedContent, pgpKey)
	if err != nil {
		log.Print(fmt.Sprintf("Failed to decrypt secret: %s", err))
	}

	metadata := v1structs.SecretMetadata{}
	jsonMetadata, err := decrypt(encryptedSecret.EncryptedMetadata, pgpKey)
	if err != nil {
		log.Print(fmt.Sprintf("Failed to decrypt secret metadata: %s", err))
	}
	err = json.NewDecoder(strings.NewReader(jsonMetadata)).Decode(&metadata)
	if err != nil {
		log.Print(fmt.Sprintf("Failed to decode secret metadata: %s", err))
	}
	uuid, err := uuid.FromString(metadata.SecretUUID)
	if err != nil {
		log.Print(fmt.Sprintf("Failed to parse uuid from string: %s", err))
	}
	fingerprint := pgpKey.Fingerprint()

	secret := secret{
		decryptedContent:  decryptedContent,
		UUID:              uuid,
		sentToFingerprint: &fingerprint,
	}
	return &secret, nil
}

func decrypt(encrypted string, pgpKey *pgpkey.PgpKey) (string, error) {
	buffer := strings.NewReader(encrypted)
	block, err := armor.Decode(buffer)
	if err != nil {
		return "", fmt.Errorf("error decoding armor: %s", err)
	}

	var keyRing openpgp.EntityList = []*openpgp.Entity{&pgpKey.Entity}

	messageDetails, err := openpgp.ReadMessage(block.Body, keyRing, nil, nil)
	if err != nil {
		return "", fmt.Errorf("error reading message: %s", err)
	}

	messageBuffer := bytes.NewBuffer(nil)
	_, err = io.Copy(messageBuffer, messageDetails.UnverifiedBody)
	if err != nil {
		return "", fmt.Errorf("error reading message: %s", err)
	}

	return messageBuffer.String(), nil
}

func countDigits(i int) (count int) {
	iString := strconv.Itoa(i)
	return len(iString)
}

const (
	secretDividerRune   = "─"
	secretDividerLength = 30
)

type secret struct {
	decryptedContent  string
	UUID              uuid.UUID
	sentToFingerprint *fingerprint.Fingerprint
}

type errListSecrets struct {
	originalError error
}

func (e errListSecrets) Error() string { return e.originalError.Error() }

type errNoSecretsFound struct{}

func (e errNoSecretsFound) Error() string { return "" }

type errDecryptPrivateKey struct {
	originalError error
}

func (e errDecryptPrivateKey) Error() string { return e.originalError.Error() }

type downloadedSecrets map[fingerprint.Fingerprint][]string
