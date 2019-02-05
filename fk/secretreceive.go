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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	homedir "github.com/mitchellh/go-homedir"

	"github.com/atotto/clipboard"
	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/crypto/openpgp/packet"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	fp "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
)

func secretReceive() exitCode {
	out.Print("\n")
	keys, err := loadPgpKeys()
	prompter := interactiveYesNoPrompter{}

	if err != nil {
		printFailed("Couldn't load PGP keys")
		return 1
	}

	out.Print(colour.Info("Downloading secrets...") + "\n\n")

	sawError := false

	secretLister := client

	for _, key := range keys {
		if !Config.ShouldPublishToAPI(key.Fingerprint()) {
			message := "Key not uploaded to Fluidkeys, can't receive secrets"
			out.Print("⛔ " + displayName(&key) + ": " + colour.Warning(message) + "\n")
			continue
		}
		encryptedSecrets, err := downloadEncryptedSecrets(key.Fingerprint(), secretLister)
		if err != nil {
			switch err.(type) {
			case errNoSecretsFound:
				out.Print("📭 " + displayName(&key) + ": No secrets found\n")
			default:
				out.Print("📪 " + displayName(&key) + ": " + colour.Failure(err.Error()) + "\n")
			}
			continue
		}

		privateKey, _, err := getDecryptedPrivateKeyAndPassword(&key, &interactivePasswordPrompter{})
		if err != nil {
			message := fmt.Sprintf("Error getting private key and password: %s", err)
			out.Print("📪 " + displayName(&key) + ": " + colour.Failure(message) + "\n")
			continue
		}
		decryptedSecrets, secretErrors := decryptSecrets(encryptedSecrets, privateKey)

		out.Print("📬 " + displayName(&key) + ":\n\n")

		secretCount := len(decryptedSecrets)

		out.Print(humanize.Pluralize(secretCount, "secret", "secrets") + ":\n\n")

		for _, secret := range decryptedSecrets {
			out.Print(formatSecretListItem(secret.decryptedContent, secret.filename))
			if secret.filename != "" {
				filenameToWrite, err := getFileNameToWrite(secret.filename)
				if err != nil {
					printFailed("Error prompting to save file to disk:")
					printFailed(err.Error())
				}
				if prompter.promptYesNo("Save to "+filenameToWrite+"?", "", nil) == true {
					err := ioutil.WriteFile(filenameToWrite, []byte(secret.decryptedContent), 0644)
					if err != nil {
						printFailed(err.Error())
					}
				}
			} else {
				if prompter.promptYesNo("Copy to clipboard?", "", nil) == true {
					err := clipboard.WriteAll(secret.decryptedContent)
					if err != nil {
						printFailed(err.Error())
					}
				}
			}
			if prompter.promptYesNo("Delete now?", "Y", nil) == true {
				err := client.DeleteSecret(key.Fingerprint(), secret.UUID.String())
				if err != nil {
					log.Printf("failed to delete secret '%s': %v", secret.UUID, err)
					printFailed("Error trying to delete secret:")
					printFailed(err.Error())
				}
			}
		}

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
	}
	return 0
}

func downloadEncryptedSecrets(fingerprint fp.Fingerprint, secretLister listSecretsInterface) (
	secrets []v1structs.Secret, err error) {
	encryptedSecrets, err := secretLister.ListSecrets(fingerprint)
	if err != nil {
		return nil, err
	}
	if len(encryptedSecrets) == 0 {
		return nil, errNoSecretsFound{}
	}
	return encryptedSecrets, nil
}

func decryptSecrets(encryptedSecrets []v1structs.Secret, privateKey *pgpkey.PgpKey) (
	secrets []secret, secretErrors []error) {
	for _, encryptedSecret := range encryptedSecrets {
		secret, err := decryptAPISecret(encryptedSecret, privateKey)
		if err != nil {
			secretErrors = append(secretErrors, err)
		} else {
			secrets = append(secrets, *secret)
		}
	}
	return secrets, secretErrors
}

func formatSecretListItem(decryptedContent string, filename string) (output string) {
	trimmedDivider := strings.Repeat(secretDividerRune, secretDividerLength-(1))
	output = out.NoLogCharacter + trimmedDivider + "\n"
	if filename != "" {
		output = output + colour.File("Filename: "+filename) + "\n"
	}
	output = output + decryptedContent
	if !strings.HasSuffix(decryptedContent, "\n") {
		output = output + "\n"
	}
	output = output + strings.Repeat(secretDividerRune, secretDividerLength) + "\n"
	return output
}

func decryptAPISecret(
	encryptedSecret v1structs.Secret, privateKey decryptorInterface) (*secret, error) {

	if encryptedSecret.EncryptedContent == "" {
		return nil, fmt.Errorf("encryptedSecret.EncryptedContent can not be empty")
	}
	if encryptedSecret.EncryptedMetadata == "" {
		return nil, fmt.Errorf("encryptedSecret.EncryptedMetadata can not be empty")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("privateKey can not be nil")
	}

	decryptedContent, literalData, err := privateKey.DecryptArmoredToString(encryptedSecret.EncryptedContent)
	if err != nil {
		log.Printf("Failed to decrypt secret: %s", err)
		return nil, fmt.Errorf("error decrypting secret: %v", err)
	}

	metadata := v1structs.SecretMetadata{}
	jsonMetadata, _, err := privateKey.DecryptArmored(encryptedSecret.EncryptedMetadata)
	if err != nil {
		log.Printf("Failed to decrypt secret metadata: %s", err)
		return nil, fmt.Errorf("error decrypting secret metadata: %v", err)
	}
	err = json.NewDecoder(jsonMetadata).Decode(&metadata)
	if err != nil {
		log.Printf("Failed to decode secret metadata: %s", err)
		return nil, fmt.Errorf("error decoding secret metadata: %v", err)
	}
	uuid, err := uuid.FromString(metadata.SecretUUID)
	if err != nil {
		log.Printf("Failed to parse uuid from string: %s", err)
		return nil, fmt.Errorf("error decoding secret metadata: %v", err)
	}

	decryptedSecret := secret{
		decryptedContent: decryptedContent,
		UUID:             uuid,
	}

	if !literalData.ForEyesOnly() {
		decryptedSecret.filename = literalData.FileName
	}

	return &decryptedSecret, nil
}

func countDigits(i int) (count int) {
	iString := strconv.Itoa(i)
	return len(iString)
}

func getFileNameToWrite(filename string) (string, error) {
	userDir, err := homedir.Dir()
	if err != nil {
		return "", err
	}
	downloadsDir := userDir + "/Downloads"
	fileInfo, err := os.Stat(downloadsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf(downloadsDir + " directory doesn't exist")
		} else {
			return "", err
		}
	}
	if !fileInfo.IsDir() {
		return "", fmt.Errorf(fileInfo.Name() + " file exists and is not a directory")
	}
	filenameToWrite := getNewUniqueFilename(
		filepath.FromSlash(downloadsDir+"/"+filename),
		doesntExist,
	)

	return filenameToWrite, nil
}

func getNewUniqueFilename(fp string, checker func(string) bool) string {
	i := 0
	foundFilename := false
	filename := filepath.Base(fp)
	numberedFilename := filename
	for ok := true; ok; ok = (foundFilename == false) {
		if i == 0 {
			// try using the original filename it was sent as first with no count suffix
			numberedFilename = filename
		} else if i > 0 {
			// the original filename already exists, try `filename(i).ext` next...
			numberedFilename = fmt.Sprintf(
				"%s(%d)%s",
				FilenameWithoutExtension(filename), i, path.Ext(filename),
			)
		}
		if checker(filepath.FromSlash(filepath.Dir(fp) + "/" + numberedFilename)) {
			foundFilename = true
		} else {
			i++
		}
	}
	return numberedFilename
}

func doesntExist(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return true
		}
	}
	return false
}

func FilenameWithoutExtension(fn string) string {
	return strings.TrimSuffix(fn, path.Ext(fn))
}

const (
	secretDividerRune   = "─"
	secretDividerLength = 30
)

type secret struct {
	decryptedContent string
	filename         string
	UUID             uuid.UUID
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

type listSecretsInterface interface {
	ListSecrets(fingerprint fingerprint.Fingerprint) ([]v1structs.Secret, error)
}

type decryptorInterface interface {
	DecryptArmored(encrypted string) (io.Reader, *packet.LiteralData, error)
	DecryptArmoredToString(encrypted string) (string, *packet.LiteralData, error)
}
