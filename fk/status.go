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
	"log"
	"time"

	docopt "github.com/docopt/docopt-go"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/status"
	"github.com/fluidkeys/fluidkeys/table"
	"github.com/fluidkeys/fluidkeys/ui"
)

func statusSubcommand(args docopt.Opts) exitCode {
	out.Print("\n")

	groupedMemberships, err := user.GroupedMemberships()
	if err != nil {
		log.Panic(err)
	}

	allKeysWithWarnings := []table.KeyWithWarnings{}

	for _, groupedMembership := range groupedMemberships {
		printHeader(groupedMembership.Team.Name)

		adminOfTeam := false

		teamKeysWithWarnings := []table.KeyWithWarnings{}

		for _, membership := range groupedMembership.Memberships {
			key, err := loadPgpKey(membership.Me.Fingerprint)
			if err != nil {
				out.Print(ui.FormatFailure(
					"Failed to load key associated with team "+membership.Team.Name,
					[]string{
						"Tried to load key " + membership.Me.Fingerprint.Hex(),
					},
					err,
				))
				return 1
			}

			keyWithWarnings := table.KeyWithWarnings{
				Key:      key,
				Warnings: status.GetKeyWarnings(*key, &Config),
			}

			teamKeysWithWarnings = append(teamKeysWithWarnings, keyWithWarnings)
			allKeysWithWarnings = append(allKeysWithWarnings, keyWithWarnings)
			if membership.Me.IsAdmin {
				adminOfTeam = true
			}
		}
		out.Print(table.FormatKeyTable(teamKeysWithWarnings))

		peopleRows := []table.PersonRow{}
		for _, person := range groupedMembership.Team.People {
			lastFetched, err := db.GetLast("fetch", person.Fingerprint)
			if err != nil {
				continue
			}
			var roughDurationSinceLastFetched string
			if lastFetched.IsZero() {
				roughDurationSinceLastFetched = "Never"
			} else {
				roughDurationSinceLastFetched = humanize.RoughDuration(
					time.Since(lastFetched),
				) + " ago"
			}
			peopleRows = append(
				peopleRows, table.PersonRow{
					Email:              person.Email,
					IsAdmin:            person.IsAdmin,
					TimeSinceLastFetch: roughDurationSinceLastFetched,
				},
			)
		}

		out.Print(table.FormatPeopleTable(peopleRows))

		if adminOfTeam {
			out.Print(ui.FormatInfo("Invite others to join the team", []string{
				"Your team members can request to join the team by running",
				colour.Cmd("fk team join " + groupedMembership.Team.UUID.String()),
			}))
		}

		out.Print("To fetch and store team members keys run " + colour.Cmd("fk team fetch") + "\n\n")

		out.Print(table.FormatKeyTablePrimaryInstruction(allKeysWithWarnings))
	}

	return 0
}
