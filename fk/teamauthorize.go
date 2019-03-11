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

	var team team.Team
	var adminKey pgpkey.PgpKey

	switch len(teamAndKeys) {
	case 0:
		out.Print(ui.FormatFailure("You aren't an admin of any teams", nil, nil))
		return 1

	case 1:
		team = teamAndKeys[0].team
		adminKey = teamAndKeys[0].adminKey

		break

	default:
		out.Print(ui.FormatFailure("Choosing from multiple teams not implemented", nil, nil))
		return 1
	}

	out.Print(ui.FormatInfo(
		"Authorizing a key adds it to the team roster",
		[]string{
			"By authorizing a key, everyone in your team will fetch and trust that key.",
		},
	))

	printHeader("Authorize keys")

	requests, err := client.ListRequestsToJoinTeam(team.UUID, adminKey.Fingerprint())
	if err != nil {
		out.Print(ui.FormatFailure("Error getting requests  keys", nil, err))
		return 1
	}

	for index, request := range requests {
		out.Print(strconv.Itoa(index+1) + ". " + request.Email + "\n")
	}

	out.Print(ui.FormatFailure("Not implemented", nil, nil))
	return 1
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
