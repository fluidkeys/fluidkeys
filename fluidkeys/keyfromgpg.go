package main

import (
	"fmt"
	"strconv"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
)

func keyFromGpg() exitCode {
	availableKeys, err := keysAvailableToGetFromGpg()
	if err != nil {
		out.Print(fmt.Sprintf("Failed to list available keys: %v", err))
		return 1
	}

	if len(availableKeys) == 0 {
		out.Print(fmt.Sprintf("No secret keys found in GPG\n"))
		return 1
	}

	out.Print(formatListedKeysForImportingFromGpg(availableKeys))
	keyToImport := promptForKeyToImportFromGpg(availableKeys)

	if keyToImport == nil {
		out.Print("No key selected to link\n")
		return 0
	}

	db.RecordFingerprintImportedIntoGnuPG(keyToImport.Fingerprint)
	Config.SetStorePassword(keyToImport.Fingerprint, false)
	Config.SetMaintainAutomatically(keyToImport.Fingerprint, false)
	out.Print("The key has been linked to Fluidkeys\n")
	return keyList()
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
	str := fmt.Sprintf("Found %s in GnuPG:\n\n", humanize.Pluralize(len(secretKeyListings), "key", "keys"))
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

		if prompter.promptYesNo("Import key?", "y", nil) {
			return &onlyKey
		} else {
			return nil
		}
	} else {
		invalidEntry := fmt.Sprintf("Please select between 1 and %v.\n", len(secretKeyListings))
		for validInput := false; !validInput; {
			rangePrompt := colour.Info(fmt.Sprintf("[1-%v]", len(secretKeyListings)))
			input := promptForInput(fmt.Sprintf(PromptWhichKeyFromGPG + " " + rangePrompt + " "))
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
