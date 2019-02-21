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
	"unicode/utf8"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/emailutils"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/stringutils"
	"github.com/fluidkeys/fluidkeys/ui"
)

func teamCreate() exitCode {
	out.Print("\n")

	out.Print("A Team is a group of people using Fluidkeys together.\n\n")
	out.Print("Fluidkeys automates configuration and key exchange for the team.\n\n")
	out.Print("This makes it easy to send secrets to one another and use other popular\n")
	out.Print("PGP tools.\n\n")

	printHeader("Which is your team email address?")

	keys, err := loadPgpKeys()
	if err != nil {
		out.Print(ui.FormatFailure("Error loading pgp keys", nil, err))
		return 1
	}

	if len(keys) == 0 {
		out.Print(ui.FormatWarning(
			"No keys found in fluidkeys", []string{
				"Before creating a team you must create a key by running ",
				"    " + colour.Cmd("fk setup"),
			},
			nil,
		))
		return 1
	}

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
	out.Print("If your team email address isn't listed, quit and run " +
		colour.Cmd("fk key create") + "\n")
	out.Print("\n")
	key := promptForTeamEmail(keys)

	printHeader("What's your team name?")

	out.Print("This is how your team will be displayed to you and other members. You can\n")
	out.Print("always change this later.\n\n")

	var teamName string

	for teamName == "" {
		teamName, err = validateTeamName(promptForInput("[team name] : "))
		if err != nil {
			printWarning(err.Error())
		}
	}

	printHeader("Who would you like to invite into " + teamName + "?")

	out.Print("One by one, add the emails of the people you'd like to invite to join.\n")
	out.Print("You can always invite others later.\n\n")
	out.Print("Finish by entering a blank address\n\n")

	var teamMemberEmails []string

	for {
		memberEmail := promptForInput("[email] : ")
		if memberEmail == "" {
			break
		}
		if !emailutils.RoughlyValidateEmail(memberEmail) {
			printWarning("Not a valid email address")
			continue
		}
		teamMemberEmails = append(teamMemberEmails, memberEmail)
	}

	printHeader("Searching gpg for existings keys")

	for _, teamMemberEmail := range teamMemberEmails {
		printCheckboxPending(teamMemberEmail)

		publicKeyListings, err := gpg.ListPublicKeys(teamMemberEmail)
		if err != nil {
			printCheckboxFailure(teamMemberEmail, err)
		}
		switch {
		case len(publicKeyListings) == 0:
			printCheckboxSkipped(
				colour.Disabled(teamMemberEmail + " no key found, you can invite them later"))

		case len(publicKeyListings) > 1:
			printCheckboxSkipped(fmt.Sprintf("%s\nmultiple keys found: skipping", teamMemberEmail))

		case len(publicKeyListings) == 1:
			printCheckboxSuccess(
				fmt.Sprintf("%s\n%*sfound key %s", teamMemberEmail, 9, " ",
					publicKeyListings[0].Fingerprint))

		}
	}
	out.Print("\n")

	printHeader("Finishing setup")

	out.Print("You've indicated you want setup " + teamName + " using your key\n")
	out.Print(fmt.Sprintf("%s\n", key.Fingerprint()))

	out.Print(ui.FormatWarning("Teams are not currently implemented", []string{
		"This feature is coming soon.",
	}, nil))

	return 1
}

func validateTeamName(teamName string) (string, error) {
	if teamName == "" {
		return "", fmt.Errorf("Team name was blank")
	}
	if !utf8.ValidString(teamName) || stringutils.ContainsDisallowedRune(teamName) {
		return "", fmt.Errorf("Team name contained invalid characters")
	}
	return teamName, nil
}

func promptForTeamEmail(keys []pgpkey.PgpKey) *pgpkey.PgpKey {
	var selectedKey int
	if len(keys) == 1 {
		onlyKey := keys[0]
		prompter := interactiveYesNoPrompter{}
		if prompter.promptYesNo("Is this your team email?", "y", nil) {
			return &onlyKey
		}
		return nil
	} else {
		invalidEntry := fmt.Sprintf("Please select between 1 and %v.\n", len(keys))
		for validInput := false; !validInput; {
			rangePrompt := colour.Info(fmt.Sprintf("[1-%v]", len(keys)))
			input := promptForInput(fmt.Sprintf(promptWhichKeyFromGPG + " " + rangePrompt + " "))
			if integerSelected, err := strconv.Atoi(input); err != nil {
				out.Print(invalidEntry)
			} else {
				if (integerSelected >= 1) && (integerSelected <= len(keys)) {
					selectedKey = integerSelected - 1
					validInput = true
				} else {
					out.Print(invalidEntry)
				}
			}
		}
		return &keys[selectedKey]
	}
}
