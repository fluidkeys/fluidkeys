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
	"path/filepath"
	"strconv"
	"unicode/utf8"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/stringutils"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/fluidkeys/fluidkeys/ui"
	"github.com/gofrs/uuid"
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

	email, err := key.Email()
	if err != nil {
		out.Print(ui.FormatFailure("Couldn't get email address for key", nil, err))
		return 1
	}

	teamMembers := []team.Person{{Email: email, Fingerprint: key.Fingerprint()}}

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

	printHeader("Creating signed team roster")

	uuid, err := uuid.NewV4()
	if err != nil {
		out.Print(ui.FormatFailure("Error creating UUID for team", nil, err))
		return 1
	}

	t := team.Team{
		UUID:   uuid,
		Name:   teamName,
		People: teamMembers,
	}

	err = t.Validate()
	if err != nil {
		out.Print(ui.FormatFailure("Something went wrong, invalid team", nil, err))
		return 1
	}
	roster, err := t.Roster()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to create roster", nil, err))
		return 1
	}

	out.Print("Create team roster with you in it:\n\n")

	out.Print(formatFileDivider("roster.toml", 80) + "\n")
	out.Print(roster)
	out.Print(formatFileDivider("", 80) + "\n")

	out.Print("\n")

	prompter := interactiveYesNoPrompter{}
	if !prompter.promptYesNo("Sign and upload the roster to Fluidkeys now?", "", nil) {
		return 1
	}

	privateKey, _, err := getDecryptedPrivateKeyAndPassword(key, &interactivePasswordPrompter{})

	printCheckboxPending("Create signed team roster")
	roster, signature, err := team.SignAndSave(t, fluidkeysDirectory, privateKey)
	if err != nil {
		printCheckboxFailure("Create signed team roster", err)
	}
	printCheckboxSuccess("Create signed team roster in \n" +
		"         " + filepath.Join(fluidkeysDirectory, "teams")) // account for checkbox indent

	action := "Upload team roster to Fluidkeys"
	printCheckboxPending(action)
	signerFingerprint := privateKey.Fingerprint()
	err = client.UpsertTeam(roster, signature, &signerFingerprint)
	if err != nil {
		printCheckboxFailure(action, err)
	}
	printCheckboxSuccess(action)
	out.Print("\n")

	printSuccess("Successfully created " + teamName)
	out.Print("\n")

	printHeader("Invite people to join the team")

	out.Print(formatFileDivider("Invitation to join "+t.Name, 80) + "\n\n")

	out.Print(`Join ` + t.Name + ` on Fluidkeys

I've created a team on Fluidkeys to make it simple for us to share passwords
and secrets securely.

Join now:

1. download Fluidkeys from https://download.fluidkeys.com

2. join the team by running:

> fk team join ` + t.UUID.String() + `

`)
	out.Print(formatFileDivider("", 80) + "\n\n")

	out.Print(colour.Instruction("👆 Copy the invitation above and send it to your team.") + "\n\n")

	promptForInput("Press enter to continue. ")

	out.Print(ui.FormatInfo("You'll need to authorize requests to join the team with "+
		colour.Cmd("fk team authorize"), []string{
		"If you're already using gpg with your team, you can pre-authorise them now",
		"by running " + colour.Cmd("fk team from-gpg"),
	},
	))

	return 0
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
			input := promptForInput(fmt.Sprintf("Which is your team email? " + rangePrompt + " "))
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
