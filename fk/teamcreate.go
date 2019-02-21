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
	"unicode/utf8"

	"github.com/fluidkeys/fluidkeys/emailutils"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/stringutils"
	"github.com/fluidkeys/fluidkeys/ui"
)

func teamCreate() exitCode {
	out.Print("\n")

	out.Print("A Team is a group of people using Fluidkeys together.\n\n")
	out.Print("Fluidkeys automates configuration and key exchange for the team.\n\n")
	out.Print("This makes it easy to send secrets to one another and use other popular\n")
	out.Print("PGP tools.\n\n")

	printHeader("What's your team name?")

	out.Print("This is how your team will be displayed to you and other members. You can\n")
	out.Print("always change this later.\n\n")

	var teamName string
	var err error

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

	printHeader("Finishing setup")

	out.Print("You've indicated you want to invite the following members to " +
		teamName + ":\n\n")
	for _, memberEmail := range teamMemberEmails {
		out.Print(memberEmail + "\n")
	}

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
