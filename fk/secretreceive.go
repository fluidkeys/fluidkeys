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
	"github.com/fluidkeys/fluidkeys/stringutils"
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
			out.Print(formatSecretListItem(
				secret.decryptedContent, secret.originalFilename),
			)
			if secret.originalFilename != "" {

				err := promptAndWriteToDownloads(secret, &prompter)
				if err != nil {
					printFailed("Error saving file:")
					printFailed(err.Error())
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

func promptAndWriteToDownloads(secret secret, prompter promptYesNoInterface) error {
	downloadsDir, err := getDownloadsDir()
	if err != nil {
		return fmt.Errorf("Error getting downloads directory: %v", err)
	}

	filename, err := getAvailableFilename(
		downloadsDir, secret.originalFilename, &fileSafeToWriteChecker{})

	if err != nil {
		return fmt.Errorf("Error finding available filename in %s: %v", downloadsDir, err)
	}

	if prompter.promptYesNo("Save to "+filename+"?", "", nil) == true {
		err := ioutil.WriteFile(filename, []byte(secret.decryptedContent), 0600)

		if err != nil {
			return fmt.Errorf("Error writing file %s: %v", filename, err)
		}
	}
	return nil
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

	if literalData.IsBinary {
		return nil, fmt.Errorf("got binary data, expected text")
	}

	if stringutils.ContainsDisallowedRune(decryptedContent) {
		return nil, fmt.Errorf("secret contained invalid characters")
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
		originalFilename: populateOriginalFilename(literalData),
	}

	return &decryptedSecret, nil
}

func populateOriginalFilename(literalData *packet.LiteralData) string {
	if literalData.ForEyesOnly() {
		// don't save to disk: don't return a filename
		return ""
	}

	if literalData.FileName != "" {
		// strip paths, e.g. /home/someone/.bashrc -> `.bashrc`
		return filepath.Base(literalData.FileName)
	}

	return ""
}

func countDigits(i int) (count int) {
	iString := strconv.Itoa(i)
	return len(iString)
}

// getAvailableFilename looks in the downloads directory for a non-existent file with the
// requestedFilename. If the filename exists, it tries numbered alternatives, e.g.
// `secret.txt` -> `~/Downloads/secret.txt` or `~/Downloads/secret(1).txt`
func getAvailableFilename(
	directory string,
	requestedFilename string,
	checker fileSafeToWriteInterface) (string, error) {

	possibleBasenames := generateIncrementedFilenames(requestedFilename)
	for _, possibleBasename := range possibleBasenames {
		filenameToWrite := filepath.Join(directory, possibleBasename)

		if checker.IsSafeToWrite(filenameToWrite) {
			return filenameToWrite, nil
		}
	}
	return "", fmt.Errorf("tried %s, %s, %s...",
		possibleBasenames[0], possibleBasenames[1], possibleBasenames[2])
}

// generateIncrementedFilenames returns 11 possible basenames e.g.
// ["file.txt", "file(1).txt", "file(2).txt" .. "file(10).txt"]
func generateIncrementedFilenames(basename string) []string {
	basenames := []string{
		basename,
	}

	for i := 1; i <= 10; i += 1 {
		beforeDot, afterDot := splitFileExtension(basename)

		numberedFilename := fmt.Sprintf("%s(%d)%s", beforeDot, i, afterDot)
		basenames = append(basenames, numberedFilename)
	}
	return basenames
}

func getDownloadsDir() (downloadsDir string, err error) {
	if xdg := os.Getenv("XDG_DOWNLOAD_DIR"); xdg != "" {
		log.Printf("using XDG_DOWNLOAD_DIR: %s", xdg)
		downloadsDir = xdg
	} else {
		userDir, err := homedir.Dir()
		if err != nil {
			return "", err
		}
		downloadsDir = filepath.Join(userDir, "Downloads")
	}

	if !directoryExists(downloadsDir) {
		return "", fmt.Errorf("directory doesn't exist or is unwritable: %s", downloadsDir)
	}

	log.Printf("downloads directory: %s\n", downloadsDir)
	return downloadsDir, nil
}

func directoryExists(directory string) bool {
	fileInfo, err := os.Stat(directory)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("directory doesn't exist: %s", directory)
			return false
		} else {
			log.Printf("os.Stat(%s) error: %v", directory, err)
			return false
		}
	}
	return fileInfo.IsDir()
}

type fileSafeToWriteChecker struct{}

func (f *fileSafeToWriteChecker) IsSafeToWrite(fullFilename string) bool {
	if _, err := os.Stat(fullFilename); err != nil {
		if os.IsNotExist(err) {
			return true
		}
	}
	return false
}

func splitFileExtension(basename string) (string, string) {
	extension := path.Ext(basename)

	return strings.TrimSuffix(basename, extension), extension
}

const (
	secretDividerRune   = "─"
	secretDividerLength = 30
)

type secret struct {
	decryptedContent string

	// originalFilename should be the (base) filename of the secret file on the sender's
	// machine, e.g. `secret.txt`.
	// Warning: don't trust that it's a basename, assume it might be e.g. `/etc/passwd`
	originalFilename string
	UUID             uuid.UUID
}

type errNoSecretsFound struct{}

func (e errNoSecretsFound) Error() string { return "" }

type errDecryptPrivateKey struct {
	originalError error
}

func (e errDecryptPrivateKey) Error() string { return e.originalError.Error() }

type fileSafeToWriteInterface interface {
	IsSafeToWrite(fullFilename string) bool
}

type listSecretsInterface interface {
	ListSecrets(fingerprint fingerprint.Fingerprint) ([]v1structs.Secret, error)
}

type decryptorInterface interface {
	DecryptArmored(encrypted string) (io.Reader, *packet.LiteralData, error)
	DecryptArmoredToString(encrypted string) (string, *packet.LiteralData, error)
}
