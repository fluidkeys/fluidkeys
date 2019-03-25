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
	"strconv"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/fluidkeys/fluidkeys/ui"
)

func teamAuthorize() exitCode {
	keys, err := loadPgpKeys()
	if err != nil {
		out.Print(ui.FormatFailure("Error loading keys", nil, err))
		return 1
	}

	allTeams, err := team.LoadTeams(fluidkeysDirectory)
	if err != nil {
		out.Print(ui.FormatFailure("Error loading teams", nil, err))
		return 1
	}

	teamAndKeys, code := getTeamsOfWhichImAdmin(allTeams, keys)
	if code != 0 {
		return code
	}

	switch len(teamAndKeys) {
	case 0:
		out.Print(ui.FormatFailure("You aren't an admin of any teams", nil, nil))
		return 1

	case 1:
		myTeam := teamAndKeys[0].team
		adminKey := teamAndKeys[0].adminKey

		printHeader("Authorize keys")

		out.Print(ui.FormatInfo(
			"Authorizing a key adds it to the team roster",
			[]string{
				"By authorizing a key, everyone in your team will fetch and trust that key.",
				"",
				"It's important to carefully check the key and email for each request.",
			},
		))

		requests, err := client.ListRequestsToJoinTeam(myTeam.UUID, adminKey.Fingerprint())
		if err != nil {
			out.Print(ui.FormatFailure("Error getting requests", nil, err))
			return 1
		}
		if len(requests) == 0 {
			out.Print("No requests to join " + myTeam.Name + "\n")
			return 0
		}

		approvedRequests := reviewRequests(requests, myTeam)

		if len(approvedRequests) > 0 {
			for _, request := range approvedRequests {
				myTeam.UpsertPerson(
					team.Person{
						Email:       request.Email,
						Fingerprint: request.Fingerprint,
						IsAdmin:     false,
					})
			}

			out.Print("The team roster is a signed file that defines who is in the team.\n\n")
			if err := promptAndSignAndUploadRoster(myTeam, &adminKey); err != nil {
				out.Print(ui.FormatFailure("Failed to sign and upload roster", nil, err))
				return 1
			}

		}

		seenError := false

		for _, request := range requests {
			if err = client.DeleteRequestToJoinTeam(myTeam.UUID, request.UUID); err != nil {
				out.Print(ui.FormatWarning(
					"Failed to delete a request to join the team", nil, err,
				))
				seenError = true
			}
		}

		if seenError {
			return 1
		}

		return 0

	default:
		out.Print(ui.FormatFailure("Choosing from multiple teams not implemented", nil, nil))
		return 1
	}
}

func reviewRequests(requests []team.RequestToJoinTeam, myTeam team.Team) (
	approvedRequests []team.RequestToJoinTeam) {

	out.Print(humanize.Pluralize(len(requests), "request", "requests") + " to join " +
		myTeam.Name + ":\n\n")

	for index, request := range requests {
		out.Print(strconv.Itoa(index+1) + ". " + request.Email + "\n")
	}
	out.Print("\n")

	prompter := interactiveYesNoPrompter{}
	for _, request := range requests {
		out.Print("» key:   " + colour.Info(request.Fingerprint.String()) + "\n")
		out.Print("  email: " + colour.Info(request.Email) + "\n")

		err, existingPerson := myTeam.GetUpsertPersonWarnings(team.Person{
			Email:       request.Email,
			Fingerprint: request.Fingerprint,
		})

		if err != nil {
			switch err {
			case team.ErrPersonWouldNotBeChanged:
				out.Print(ui.FormatWarning(
					"This person is already in the team", []string{
						"Skipping.",
					},
					nil,
				))
				continue
			case team.ErrEmailWouldBeUpdated:
				out.Print(ui.FormatWarning(
					"A key with this fingerprint is already in the team", []string{
						"Existing key belonging to " + existingPerson.Email,
						"will be replaced.",
					},
					nil,
				))
			case team.ErrKeyWouldBeUpdated:
				out.Print(ui.FormatWarning(
					existingPerson.Email+" is already in the team", []string{
						"Existing key " + existingPerson.Fingerprint.String(),
						"will be replaced.",
					},
					nil,
				))
			case team.ErrPersonWouldBeDemotedAsAdmin:
				out.Print(ui.FormatWarning(
					existingPerson.Email+" is already in the team", []string{
						"Adding them will demote them from being admin.",
					},
					nil,
				))
			case team.ErrPersonWouldBePromotedToAdmin:
				out.Print(ui.FormatWarning(
					existingPerson.Email+" is already in the team", []string{
						"Adding them will promote them to being admin.",
					},
					nil,
				))
			}
		} else {
			out.Print("\n")
		}

		addToTeam := prompter.promptYesNo("Authorize this key for "+request.Email+
			" and add to team roster?", "", nil)

		if addToTeam {
			approvedRequests = append(approvedRequests, request)
		}
	}

	return approvedRequests
}

type teamAndKey struct {
	team     team.Team
	adminKey pgpkey.PgpKey
}

func getTeamsOfWhichImAdmin(allTeams []team.Team, myKeys []pgpkey.PgpKey) (
	teams []teamAndKey, code exitCode) {

	for _, team := range allTeams {
		for _, key := range myKeys {
			if team.IsAdmin(key.Fingerprint()) {
				teams = append(teams, teamAndKey{team: team, adminKey: key})
				break
			}
		}
	}

	return teams, 0
}
