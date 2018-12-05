package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"

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
		email, err := key.Email()
		if err != nil {
			printFailed("Couldn't get email for key " + key.Fingerprint().String() + "\n")
			continue
		}

		out.Print("For " + email + ":\n\n")
		if encryptedSecrets, err := client.ListSecrets(key.Fingerprint()); err != nil {
			printFailed(err.Error() + "\n")
		} else {
			if encryptedSecrets == nil {
				printInfo("No secrets found\n")
				continue
			}
			a := LoadPrivateKeyFromGnupg{}
			if privateKey, _, err := getDecryptedPrivateKeyAndPassword(&key, a.passwordGetter); err != nil {
				printFailed(fmt.Sprintf("Error getting private key and password: %s", err))
				continue
			} else {
				key = *privateKey
			}

			for _, encryptedSecret := range encryptedSecrets {
				out.Print("---\n")
				decryptedContent, err := decrypt(encryptedSecret.EncryptedContent, &key)
				if err != nil {
					printFailed(err.Error() + "\n")
				} else {
					out.Print(decryptedContent + "\n")
				}
				out.Print("---\n\n")
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
