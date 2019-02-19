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
	"fmt"
	"strconv"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/status"
)

const promptWhichKeyFromGPG string = "Which key would you like to import?"

func keyFromGpg() exitCode {
	out.Print("\n")
	availableKeys, err := keysAvailableToGetFromGpg()
	if err != nil {
		out.Print(fmt.Sprintf("Failed to list available keys: %v\n\n", err))
		return 1
	}

	if len(availableKeys) == 0 {
		out.Print(fmt.Sprintf("No new keys found with " + colour.CommandLineCode("gpg --list-secret-keys") + "\n\n"))
		out.Print("See the keys you've already connected by running:\n")
		out.Print("    " + colour.CommandLineCode("fk key list") + "\n\n")

		return 1
	}

	out.Print("Connecting a key allows Fluidkeys to inspect your key and fix any issues.\n\n")

	out.Print(formatListedKeysForImportingFromGpg(availableKeys))
	keyToImport := promptForKeyToImportFromGpg(availableKeys)

	if keyToImport == nil {
		out.Print("No key selected to link\n")
		return 0
	}

	db.RecordFingerprintImportedIntoGnuPG(keyToImport.Fingerprint)
	Config.SetStorePassword(keyToImport.Fingerprint, false)
	Config.SetMaintainAutomatically(keyToImport.Fingerprint, false)
	printSuccess("Successfully connected key to Fluidkeys")
	out.Print("\n")

	key, err := loadPgpKey(keyToImport.Fingerprint)
	if err != nil {
		out.Print(fmt.Sprintf("Failed to load key from gpg: %v\n\n", err))
		return 1
	}

	keyTask := keyTask{
		key:      key,
		warnings: status.GetKeyWarnings(*key, &Config),
	}

	out.Print(formatKeyWarnings(keyTask))

	out.Print("Fluidkeys can fix these issues. See how by running:\n")
	out.Print("    " + colour.CommandLineCode("fk key maintain --dry-run") + "\n\n")

	return 0
}

// keysAvailableToGetFromGpg returns a filtered slice of SecretKeyListings, removing
// any keys that Fluidkeys is already managing.
func keysAvailableToGetFromGpg() ([]gpgwrapper.SecretKeyListing, error) {

	importedFingerprints, err := db.GetFingerprintsImportedIntoGnuPG()
	if err != nil {
		return nil, fmt.Errorf("Failed to get fingerprints from database: %v\n", err)
	}

	var availableKeys []gpgwrapper.SecretKeyListing

	allGpgKeys, err := gpg.ListSecretKeys()
	if err != nil {
		return nil, fmt.Errorf("Error getting secret keys from GPG: %v", err)
	}

	for _, key := range allGpgKeys {
		if !fingerprint.Contains(importedFingerprints, key.Fingerprint) {
			availableKeys = append(availableKeys, key)
		}
	}
	return availableKeys, nil
}

func formatListedKeysForImportingFromGpg(secretKeyListings []gpgwrapper.SecretKeyListing) string {
	str := "Found " + humanize.Pluralize(len(secretKeyListings), "key", "keys") +
		" with " + colour.CommandLineCode("gpg --list-secret-keys") + ":\n\n"
	for index, key := range secretKeyListings {
		str += printSecretKeyListing(index+1, key)
	}
	return str
}

func printSecretKeyListing(listNumber int, key gpgwrapper.SecretKeyListing) string {
	formattedListNumber := colour.Info(fmt.Sprintf("%-4s", (strconv.Itoa(listNumber) + ".")))
	output := fmt.Sprintf("%s%s\n", formattedListNumber, key.Fingerprint)
	output += fmt.Sprintf("    Created on %s\n", key.Created.Format("2 January 2006"))
	for _, uid := range key.Uids {
		output += fmt.Sprintf("      %v\n", uid)
	}
	output += fmt.Sprintf("\n")
	return output
}

func promptForKeyToImportFromGpg(secretKeyListings []gpgwrapper.SecretKeyListing) *gpgwrapper.SecretKeyListing {
	var selectedKey int
	if len(secretKeyListings) == 1 {
		onlyKey := secretKeyListings[0]
		prompter := interactiveYesNoPrompter{}

		if prompter.promptYesNo("Connect this key?", "y", nil) {
			return &onlyKey
		} else {
			return nil
		}
	} else {
		invalidEntry := fmt.Sprintf("Please select between 1 and %v.\n", len(secretKeyListings))
		for validInput := false; !validInput; {
			rangePrompt := colour.Info(fmt.Sprintf("[1-%v]", len(secretKeyListings)))
			input := promptForInput(fmt.Sprintf(promptWhichKeyFromGPG + " " + rangePrompt + " "))
			if integerSelected, err := strconv.Atoi(input); err != nil {
				out.Print(invalidEntry)
			} else {
				if (integerSelected >= 1) && (integerSelected <= len(secretKeyListings)) {
					selectedKey = integerSelected - 1
					validInput = true
				} else {
					out.Print(invalidEntry)
				}
			}
		}
		return &secretKeyListings[selectedKey]
	}
}
