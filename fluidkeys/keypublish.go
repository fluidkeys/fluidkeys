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

func promptAndTurnOnPublishToAPI(prompter promptYesNoInterface, key *pgpkey.PgpKey) {
	out.Print("🔍 Publishing your key in the Fluidkeys directory allows\n")
	out.Print("   others to find your key from your email address.\n\n")

	if prompter.promptYesNo(promptPublishToAPI, "", key) == true {
		if err := Config.SetPublishToAPI(key.Fingerprint(), true); err != nil {
			log.Printf("Failed to enable publish to api: %v", err)
		}
	} else {
		out.Print(colour.Disabled(" ▸   Not publishing key to API.\n\n"))
	}
}
