package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/fluidkeys/fluidkeys/gpgwrapper"

	"github.com/fluidkeys/fluidkeys/out"
)

func teamCreate(teamName string) exitCode {
	out.Print("\n")

	email := promptForEmail("What’s your " + teamName + " email address?\n")

	availableKeys, err := keysAvailableToGetFromGpg()
	if err != nil {
		output := fmt.Sprintf("Couldn't retrieve keys from GPG: %v\n", err)
		out.Print(output)
		os.Exit(1)
	}

	existingKey := secretKeyListingsForEmail(availableKeys, email)
	if existingKey != nil {
		out.Print("You should use a separate key for each team.\n\n")
		out.Print(printSecretKeyListing(1, *existingKey))
		prompter := interactiveYesNoPrompter{}
		if prompter.promptYesNo("Use this key for "+teamName+"?", "y", nil) {
			importGPGKey(existingKey.Fingerprint)
		} else {
			createKeyForEmail(email)
		}
	} else {
		createKeyForEmail(email)
	}
	fmt.Printf("%v\n", existingKey)
	return 0
}

func secretKeyListingsForEmail(availableKeys []gpgwrapper.SecretKeyListing, email string) *gpgwrapper.SecretKeyListing {
	for _, listing := range availableKeys {
		if (len(listing.Uids) == 1) && (strings.Contains(listing.Uids[0], email)) {
			return &listing
		}
	}
	return nil
}
