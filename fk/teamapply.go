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
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/fluidkeys/fluidkeys/colour"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/ui"
	"github.com/gofrs/uuid"
)

func teamApply(teamUUID uuid.UUID) exitCode {
	if code := ensureUserCanJoinTeam(teamUUID); code != 0 {
		return code
	}

	teamName, err := api.GetTeamName(teamUUID)
	if err != nil {
		out.Print(ui.FormatFailure("Couldn't request to join team", nil, err))
		return 1
	}
	out.Print("\n")
	out.Print("You're applying to join the team " + teamName + "\n\n")

	pgpKey, code := getKeyForTeam()
	if code != 0 {
		return code
	}

	email, err := pgpKey.Email()
	if err != nil {
		out.Print(ui.FormatFailure("Error getting email for key", nil, err))
		return 1
	}

	if exitCode := ensureNoExistingRequests(
		teamUUID, pgpKey.Fingerprint(), email); exitCode != 0 {
		return exitCode
	}

	printHeader("Apply to join team")

	if err := requestToJoinTeam(teamUUID, teamName, pgpKey.Fingerprint(), email); err != nil {
		out.Print(ui.FormatFailure("Failed to apply to join "+teamName, nil, err))
		return 1
	}

	out.Print(ui.FormatInfo("Reply to your team admin so they can add you to the team", []string{
		"This information allows them to verify your request.",
	}))

	out.Print(formatFileDivider("Please authorize me to join Kiffix", 80) + "\n")
	requestMessage := "I've requested to join " + teamName + " on Fluidkeys.\n\n" +
		"Here are my verification details:\n\n" +
		strings.Join(formatVerificationLines(pgpKey.Fingerprint(), email), "\n") +
		"\n\n" +
		"Please can you authorize me by running\n\n" +
		"> fk team authorize\n"
	out.Print("\n" + requestMessage + "\n")

	out.Print(formatFileDivider("", 80) + "\n\n")

	prompter := interactiveYesNoPrompter{}
	if prompter.promptYesNo("Copy this message to your clipboard now?", "y", nil) == true {
		if err := clipboard.WriteAll(requestMessage); err != nil {
			out.Print(ui.FormatFailure("Failed to copy message to clipboard", nil, err))
			return 1
		}
	}

	return 0

}

func formatVerificationLines(fingerprint fpr.Fingerprint, email string) []string {
	return []string{
		"» key:   " + fingerprint.String(),
		"  email: " + email,
	}
}

func ensureUserCanJoinTeam(teamUUID uuid.UUID) exitCode {
	isInTeam, existingTeam, err := user.IsInTeam(teamUUID)
	if err != nil {
		out.Print(ui.FormatFailure("Couldn't check if user already is in team", nil, err))
		return 1
	}
	if isInTeam {
		out.Print(ui.FormatSuccess("You're already in the team "+existingTeam.Name, nil))
		return 1
	}

	memberships, err := user.Memberships()
	if err != nil {
		out.Print(ui.FormatFailure(
			"Failed to join team", []string{
				"Error checking which teams you're already a member of.",
			}, err))
		return 1
	}
	if len(memberships) > 0 {
		out.Print(ui.FormatWarning(
			"Can't join another team", []string{
				"Currently Fluidkeys only supports being in one team.",
			}, nil))
		return 1
	}
	return 0
}

func ensureNoExistingRequests(
	teamUUID uuid.UUID, fingerprint fpr.Fingerprint, email string) exitCode {

	existingRequest, err := db.GetExistingRequestToJoinTeam(teamUUID, fingerprint)
	if err != nil {
		out.Print(ui.FormatFailure("Failed to check for existing requests", nil, err))
		return 1
	}
	if existingRequest != nil {
		lines :=
			[]string{
				formatYouRequestedToJoin(*existingRequest),
				"Check if the team admin has authorized your request by running " +
					colour.Cmd("fk team fetch"),
				"",
				"Here are the verification details for your team admin:",
				"",
			}
			// NOTE: strictly, we make the verification details using the email from the request in
			// the db rather than reading it again from key. But we don't store the email in the
			// db, so that option isn't available. I don't believe this affects the verification
			// but it could lead to a confusing state.
		lines = append(lines, formatVerificationLines(existingRequest.Fingerprint, email)...)
		out.Print(ui.FormatWarning(
			"You've already requested to join "+existingRequest.TeamName, lines, nil))
		return 1
	}
	return 0
}

func requestToJoinTeam(
	teamUUID uuid.UUID, teamName string, fingerprint fpr.Fingerprint, email string) error {

	if err := db.RecordRequestToJoinTeam(teamUUID, teamName, fingerprint, time.Now()); err != nil {
		return err
	}
	if err := api.RequestToJoinTeam(teamUUID, fingerprint, email); err != nil {
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
