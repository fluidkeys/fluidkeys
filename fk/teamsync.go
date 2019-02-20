// Copyright 2019 Paul Furley and Ian Drysdale
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

	"github.com/fluidkeys/fluidkeys/api"
	"github.com/fluidkeys/fluidkeys/colour"
	fp "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/teamroster"
)

func teamSync() exitCode {
	teams, err := teamroster.Load(fluidkeysDirectory)
	if err != nil {
		log.Panic(err)
	}

	var sawError = false

	for _, team := range teams {
		out.Print("\n")
		out.Print(colour.Info(team.Name) + "\n")
		out.Print("\n")

		out.Print("Fetching keys and importing into gpg:\n\n")

		for email, person := range team.People {
			if person.Fingerprint == nil {
				printCheckboxSkipped("no fingerprint for " + email)
				sawError = true
				continue
			}

			err := getAndImportKeyToGpg(*person.Fingerprint)
			if err != nil {
				printCheckboxFailure("Fail to fetch key", err)
				sawError = true
				continue
			}

			printCheckboxSuccess(email)
		}
	}

	if sawError {
		out.Print("\n")
		printFailed("Encountered errors while syncing :(\n")
		return 1
	}
	out.Print("\n")
	printSuccess("Fetched keys for " + humanize.Pluralize(len(teams), "team", "teams") + ".")
	return 0
}

func getAndImportKeyToGpg(fingerprint fp.Fingerprint) error {
	key, err := client.GetPublicKeyByFingerprint(fingerprint)

	if err != nil && err == api.ErrPublicKeyNotFound {
		log.Print(err)
		return fmt.Errorf("Couldn't find key")
	} else if err != nil {
		log.Print(err)
		return fmt.Errorf("Got error from Fluidkeys server")
	}

	armoredKey, err := key.Armor()
	if err != nil {
		log.Print(err)
		return fmt.Errorf("failed to ASCII armor key")
	}

	err = gpg.ImportArmoredKey(armoredKey)
	if err != nil {
		log.Print(err)
		return fmt.Errorf("Failed to import key into gpg")
	}
	return nil
}
