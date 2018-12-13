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
	"fmt"
	"log"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func keyPublish() exitCode {
	out.Print(colour.Info("Publishing keys...") + "\n\n")
	keys, err := loadPgpKeys()
	if err != nil {
		panic(err)
	}

	passwordPrompter := interactivePasswordPrompter{}
	yesNoPrompter := interactiveYesNoPrompter{}

	gotAnyErrors := false

	for i := range keys {
		key := &keys[i]
		out.Print(displayName(key) + "\n\n")

		if !Config.ShouldPublishToAPI(key.Fingerprint()) {
			out.Print(colour.Warning(" ▸   Config currently preventing key from being published\n\n"))
			promptAndTurnOnPublishToAPI(&yesNoPrompter, key)
		}

		// Check again, since promptAndTurnOnPublishToAPI modifies
		// this setting if the user answers "yes"
		if !Config.ShouldPublishToAPI(key.Fingerprint()) {
			continue // they really really don't want to publish
		}

		unlockedKey, _, err := getDecryptedPrivateKeyAndPassword(key, &passwordPrompter)
		if err != nil {
			printFailed("Failed to unlock private key")
			out.Print("Error: " + err.Error() + "\n")
			gotAnyErrors = true
			continue
		}

		err = publishKeyToAPI(unlockedKey)
		if err != nil {
			printFailed("Error publishing key")
			out.Print(colour.Error("     " + err.Error() + "\n\n"))
			gotAnyErrors = true
			continue
		}

		printSuccess("Published key to Fluidkeys directory\n")
	}

	if gotAnyErrors {
		return 1
	}
	return 0
}

func publishKeyToAPI(privateKey *pgpkey.PgpKey) error {
	armoredPublicKey, err := privateKey.Armor()
	if err != nil {
		return fmt.Errorf("Couldn't load armored key: %s\n", err)
	}
	if err = client.UpsertPublicKey(armoredPublicKey, privateKey); err != nil {
		return fmt.Errorf("Failed to upload public key: %s", err)

	}
	return nil
}

// promptToEnableConfigPublishToAPI asks the user if they'd like to publish a
// key to the Fluidkeys directory.
// This actually means *enable config* to publish from subsequent actions like
// `key maintain` and `key publish`.
func promptToEnableConfigPublishToAPI(key *pgpkey.PgpKey) {
	prompter := interactiveYesNoPrompter{}

	out.Print("🔍 Publishing your key in the Fluidkeys directory allows\n")
	out.Print("   others to find your key from your email address.\n\n")

	if prompter.promptYesNo("Publish this key?", "", key) == true {
		if err := Config.SetPublishToAPI(key.Fingerprint(), true); err != nil {
			log.Printf("Failed to enable publish to api: %v", err)
		}
	} else {
		out.Print(colour.Disabled(" ▸   Not publishing key to Fluidkeys directory.\n\n"))
	}
}
