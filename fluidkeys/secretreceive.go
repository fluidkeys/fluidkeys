package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/fluidkeys/fluidkeys/humanize"

	"github.com/fluidkeys/fluidkeys/colour"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/fluidkeys/api"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func secretReceive() exitCode {
	out.Print("\n")
	client := api.NewClient()
	keys, err := loadPgpKeys()

	if err != nil {
		printFailed("Couldn't load PGP keys")
		return 1
	}

	out.Print(colour.Info("Downloading secrets...") + "\n\n")

	for _, key := range keys {
		if err != nil {
			printFailed("Couldn't get email for key " + key.Fingerprint().String() + "\n")
			continue
		}

		if encryptedSecrets, err := client.ListSecrets(key.Fingerprint()); err != nil {
			out.Print("📪 " + displayName(&key) + ": " + colour.Failure(err.Error()) + "\n")
		} else {
			if encryptedSecrets == nil {
				out.Print("📭 " + displayName(&key) + ": No secrets found\n")
				continue
			}
			a := LoadPrivateKeyFromGnupg{}
			if privateKey, _, err := getDecryptedPrivateKeyAndPassword(&key, a.passwordGetter); err != nil {
				err := fmt.Sprintf("Error getting private key and password: %s", err)
				out.Print("📪 " + displayName(&key) + ": " + colour.Failure(err) + "\n")
				continue
			} else {
				key = *privateKey
			}

			out.Print("📬 " + displayName(&key) + ":\n")

			errors := []error{}
			for i, encryptedSecret := range encryptedSecrets {
				decryptedContent, err := decrypt(encryptedSecret.EncryptedContent, &key)
				if err != nil {
					errors = append(errors, err)
				} else {
					displayCounter := strconv.Itoa(i+1) + ". "
					barLength := secretDividerLength - len(displayCounter)
					out.Print(displayCounter + strings.Repeat("─", barLength) + "\n")

					scanner := bufio.NewScanner(strings.NewReader(decryptedContent))
					for scanner.Scan() {
						out.Print(strings.Repeat(" ", len(displayCounter)) + scanner.Text() + "\n")
					}
				}
			}

			out.Print(strings.Repeat("─", secretDividerLength) + "\n")

			if len(errors) > 0 {
				output := humanize.Pluralize(len(errors), "secret", "secrets") + " failed to download for " + displayName(&key) + ":\n"
				out.Print(colour.Failure(colour.StripAllColourCodes(output)))
				for _, error := range errors {
					printFailed(error.Error())
				}
			}
		}

	}
	return 0
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
	secretDividerLength = 30
)
