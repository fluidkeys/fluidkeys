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
	"strconv"
	"time"

	"github.com/fluidkeys/fluidkeys/colour"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/ui"
	"github.com/gofrs/uuid"
)

func teamJoin(teamUUID uuid.UUID) exitCode {
	teamName, err := client.GetTeamName(teamUUID)
	if err != nil {
		out.Print(ui.FormatFailure("Couldn't request to join team", nil, err))
		return 1
	}
	out.Print("\n")
	out.Print("You're joining the team " + teamName + "\n\n")

	pgpKey, code := getKeyForTeam()
	if code != 0 {
		return code
	}

	if exitCode := ensureNoExistingRequests(teamUUID, pgpKey.Fingerprint()); exitCode != 0 {
		return exitCode
	}

	email, err := pgpKey.Email()
	if err != nil {
		out.Print(ui.FormatFailure("Error getting email for key", nil, err))
		return 1
	}

	printHeader("Requesting to join team")

	action := "Request to join " + teamName
	ui.PrintCheckboxPending("action")

	if err := requestToJoinTeam(teamUUID, teamName, pgpKey.Fingerprint(), email); err != nil {
		ui.PrintCheckboxFailure(action, err)
		return 1
	}

	ui.PrintCheckboxSuccess(action)
	out.Print("\n")

	out.Print("Your team admin will need to authorize your request for Fluidkeys to\n" +
		"start working.\n\n")
	return 0

}

func ensureNoExistingRequests(teamUUID uuid.UUID, fingerprint fpr.Fingerprint) exitCode {
	existingRequest, err := db.GetExistingRequestToJoinTeam(teamUUID, fingerprint)
	if err != nil {
		out.Print(ui.FormatFailure("Failed to check for existing requests", nil, err))
		return 1
	}
	if existingRequest != nil {
		out.Print(ui.FormatWarning(
			"You've already requested to join "+existingRequest.TeamName,
			[]string{
				formatYouRequestedToJoin(*existingRequest),
				"The admin hasn't authorized this yet.",
			},
			nil,
		))
		return 1
	}
	return 0
}

func requestToJoinTeam(
	teamUUID uuid.UUID, teamName string, fingerprint fpr.Fingerprint, email string) error {

	if err := db.RecordRequestToJoinTeam(teamUUID, teamName, fingerprint, time.Now()); err != nil {
		return err
	}
	if err := client.RequestToJoinTeam(teamUUID, fingerprint, email); err != nil {
		return err
	}
	return nil
}

func getKeyForTeam() (*pgpkey.PgpKey, exitCode) {
	var pgpKey *pgpkey.PgpKey

	keys, err := loadPgpKeys()
	if err != nil {
		out.Print(ui.FormatFailure("Error loading pgp keys", nil, err))
		return nil, 1
	}

	switch len(keys) {
	case 0: // no key yet, create one and use that
		var code exitCode
		if code, pgpKey = keyCreate(""); code != 0 {
			return nil, code
		}

	case 1: // one key in Fluidkeys, confirm it's OK to use that one
		printHeader("Confirm your team email address")

		if err := printEmailsWithNumbers(keys); err != nil {
			return nil, 1 // no need to print as the function prints its own errors
		}

		out.Print(ifNotYourTeamEmail)

		if answer := promptConfirmThisKey(&keys[0]); !answer {
			// if they said no, just exit without printing anything
			return nil, 1
		}
		pgpKey = &keys[0]

	default: // multiple keys in Fluidkeys, prompt which one to use for the team
		printHeader("Which is your team email address?")

		if err := printEmailsWithNumbers(keys); err != nil {
			return nil, 1 // no need to print as the function prints its own errors
		}

		out.Print(ifEmailNotListed)
		pgpKey = promptForKeyByNumber(keys)
	}
	return pgpKey, 0
}

func printEmailsWithNumbers(keys []pgpkey.PgpKey) error {
	for index, key := range keys {
		email, err := key.Email()
		if err != nil {
			out.Print(ui.FormatFailure(
				"Failed to get email for key", []string{
					fmt.Sprintf("%s has no identities with email addresses", key.Fingerprint()),
				},
				err,
			))
		}
		formattedListNumber := colour.Info(fmt.Sprintf("%-4s", (strconv.Itoa(index+1) + ".")))
		out.Print(fmt.Sprintf("%s%s\n", formattedListNumber, email))
	}
	out.Print("\n")
	return nil
}

func promptConfirmThisKey(key *pgpkey.PgpKey) bool {
	prompter := interactiveYesNoPrompter{}
	return prompter.promptYesNo("Is this your team email?", "y", nil)
}

func promptForKeyByNumber(keys []pgpkey.PgpKey) *pgpkey.PgpKey {
	invalidEntry := fmt.Sprintf("Please select between 1 and %v.\n", len(keys))

	inRange := func(selected int) bool {
		return 1 <= selected && selected <= len(keys)
	}

	for {
		rangePrompt := colour.Info(fmt.Sprintf("[1-%v]", len(keys)))
		input := promptForInput(fmt.Sprintf("Which is your team email? " + rangePrompt + " "))
		if integerSelected, err := strconv.Atoi(input); err != nil {
			out.Print(invalidEntry)

		} else if !inRange(integerSelected) {
			out.Print(invalidEntry)

		} else {
			return &keys[integerSelected-1]
		}
	}
}

var (
	ifEmailNotListed = "If your team email address isn't listed, quit and run " +
		colour.Cmd("fk key create") + "\n\n"

	ifNotYourTeamEmail = "If this is not the email you use in your team, quit and run " +
		colour.Cmd("fk key create") + "\n\n"
)
