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
	"errors"
	"fmt"
	"path/filepath"
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
	memberships, err := user.Memberships()
	if err != nil {
		out.Print(ui.FormatFailure(
			"Failed to create team", []string{
				"Error checking which teams you're already a member of.",
			}, err))
		return 1
	}
	if len(memberships) > 0 {
		out.Print(ui.FormatWarning(
			"Can't create another team", []string{
				"Currently Fluidkeys only supports being in one team.",
			}, nil))
		return 1
	}

	out.Print("\n")

	out.Print("A Team is a group of people using Fluidkeys together.\n\n")
	out.Print("Fluidkeys automates configuration and key exchange for the team.\n\n")
	out.Print("This makes it easy to send secrets to one another and use other popular\n")
	out.Print("PGP tools.\n\n")

	key, code := getKeyForTeam()
	if code != 0 {
		return code
	}

	email, err := key.Email()
	if err != nil {
		out.Print(ui.FormatFailure("Couldn't get email address for key", nil, err))
		return 1
	}

	teamMembers := []team.Person{{Email: email, Fingerprint: key.Fingerprint(), IsAdmin: true}}

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

	out.Print("Create team roster with you in it:\n\n")

	if err := promptAndSignAndUploadRoster(t, key); err != nil {
		if err != errUserDeclinedToSign {
			out.Print(ui.FormatFailure("Failed to sign and upload roster", nil, err))
		}
		return 1
	}

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
		colour.Cmd("fk team authorize"), nil))

	return 0
}

func promptAndSignAndUploadRoster(t team.Team, key *pgpkey.PgpKey) (err error) {
	unsignedRoster, err := t.PreviewRoster()
	if err != nil {
		return err
	}

	out.Print(formatRosterPreview(unsignedRoster))

	prompter := interactiveYesNoPrompter{}
	if !prompter.promptYesNo("Sign and upload the roster to Fluidkeys now?", "", nil) {
		return errUserDeclinedToSign
	}

	privateKey, _, err := getDecryptedPrivateKeyAndPassword(key, &interactivePasswordPrompter{})
	if err != nil {
		return fmt.Errorf("Failed to unlock private key to sign roster: %v", err)
	}

	const (
		checkboxSign   = "Created signed team roster"
		checkboxUpload = "Upload team roster to Fluidkeys"
	)

	failSign := func(err error) error {
		ui.PrintCheckboxFailure(checkboxSign, err)
		return err
	}
	failUpload := func(err error) error {
		ui.PrintCheckboxFailure(checkboxUpload, err)
		return err
	}

	ui.PrintCheckboxPending(checkboxSign)

	if err = t.UpdateRoster(privateKey); err != nil {
		return failSign(err)
	}
	signedRoster, signature := t.Roster()
	teamSubdirectory, err := team.Directory(t, fluidkeysDirectory)
	if err != nil {
		return failSign(err)
	}

	rosterSaver := team.RosterSaver{Directory: teamSubdirectory}
	if err = rosterSaver.SaveDraft(signedRoster, signature); err != nil {
		return failSign(err)
	}

	ui.PrintCheckboxPending(checkboxSign)

	if err := client.UpsertTeam(signedRoster, signature, privateKey.Fingerprint()); err != nil {
		rosterSaver.DiscardDraft()
		return failUpload(err)
	}

	if err := rosterSaver.CommitDraft(); err != nil {
		return failSign(err)
	}
	// align to checkbox indent
	ui.PrintCheckboxSuccess(checkboxSign)
	out.Print("         " + filepath.Join(fluidkeysDirectory, "teams") + "\n")
	ui.PrintCheckboxSuccess(checkboxUpload)

	return nil
}

func formatRosterPreview(roster string) string {
	return formatFileDivider("roster.toml", 80) + "\n" +
		roster +
		formatFileDivider("", 80) + "\n\n"
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

var (
	errUserDeclinedToSign = errors.New("you deliced to sign the roster")
)
