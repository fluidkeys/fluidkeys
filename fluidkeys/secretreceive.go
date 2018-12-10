package main

import (
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
	keys, err := loadPgpKeys()

	if err != nil {
		printFailed("Couldn't load PGP keys")
		return 1
	}

	out.Print(colour.Info("Downloading secrets...") + "\n\n")

	var sawError bool = false

	for _, key := range keys {
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
			out.Print(formatSecretListItem(i+1, secret))
		}

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
	if sawError {
		return 1
	} else {
		return 0
	}
}

func downloadAndDecryptSecrets(key pgpkey.PgpKey) (decryptedSecrets []string, secretErrors []error, err error) {
	client := api.NewClient()
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
		decryptedContent, err := decrypt(encryptedSecret.EncryptedContent, privateKey)
		if err != nil {
			secretErrors = append(secretErrors, err)
		} else {
			decryptedSecrets = append(decryptedSecrets, decryptedContent)
		}
	}
	return decryptedSecrets, secretErrors, nil
}

func formatSecretListItem(listNumber int, decryptedContent string) (output string) {
	displayCounter := fmt.Sprintf("%d. ", listNumber)
	trimmedDivider := strings.Repeat(secretDividerRune, secretDividerLength-len(displayCounter))
	output = displayCounter + trimmedDivider + "\n"
	output = output + decryptedContent
	if !strings.HasSuffix(decryptedContent, "\n") {
		output = output + "\n"
	}
	return output
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
