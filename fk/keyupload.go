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
	"log"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func keyUpload() exitCode {
	keys, err := loadPgpKeys()
	if err != nil {
		log.Panic(err)
	}

	passwordPrompter := interactivePasswordPrompter{}

	gotAnyErrors := false

	for i := range keys {
		key := &keys[i]
		out.Print(displayName(key) + "\n\n")

		if !shouldPublishToAPI(key) {
			continue
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
			printFailed("Error uploading key")
			out.Print(colour.Error("     " + err.Error() + "\n\n"))
			gotAnyErrors = true
			continue
		}

		printSuccess("Uploaded public key to Fluidkeys\n")
	}

	if gotAnyErrors {
		return 1
	}
	return 0
}

// shouldPublishToAPI nags the user to turn on publish to API if it's not
// already turned on.
// If it's already set, just return true.
// If it's not already set:
// * ask them if they want to publish it
// * if yes, *update the config*
// * return the current value of Config.ShouldPublishToAPI
func shouldPublishToAPI(key *pgpkey.PgpKey) bool {
	shouldPublish := Config.ShouldPublishToAPI(key.Fingerprint())

	if !shouldPublish {
		out.Print(colour.Warning(" ▸   Config file prevents key from being uploaded\n\n"))

		promptToEnableConfigPublishToAPI(key)
	}

	return Config.ShouldPublishToAPI(key.Fingerprint())
}

func publishKeyToAPI(privateKey *pgpkey.PgpKey) error {
	armoredPublicKey, err := privateKey.Armor()
	if err != nil {
		return fmt.Errorf("Couldn't load armored key: %s", err)
	}
	if err = api.UpsertPublicKey(armoredPublicKey, privateKey); err != nil {
		return fmt.Errorf("Failed to upload public key: %s", err)

	}
	return nil
}

// promptToEnableConfigPublishToAPI asks the user if they'd like to publish a
// key to the Fluidkeys directory.
// This actually means *enable config* to publish from subsequent actions like
// `key maintain` and `key upload`.
func promptToEnableConfigPublishToAPI(key *pgpkey.PgpKey) {
	prompter := interactiveYesNoPrompter{}

	out.Print("🔍 To allow others to send you secrets, you need to upload your\n")
	out.Print("   public key to Fluidkeys.\n\n")

	if prompter.promptYesNo("Upload key from now on?", "", key) == true {
		if err := Config.SetPublishToAPI(key.Fingerprint(), true); err != nil {
			log.Printf("Failed to enable publish to api: %v", err)
		}
	} else {
		out.Print(colour.Disabled(" ▸   Not uploading key\n\n"))
	}
}
