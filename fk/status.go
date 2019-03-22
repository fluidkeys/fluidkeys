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

	if code := printMemberships(); code != 0 {
		return code
	}

	if code := printRequests(); code != 0 {
		return code
	}

	if code := printOrphanedKeys(); code != 0 {
		return code
	}
	return 0
}

func printMemberships() exitCode {
	groupedMemberships, err := user.GroupedMemberships()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to load team memberships", nil, err))
		return 1
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
				roughDurationSinceLastFetched = "-"
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

		out.Print("Team keys are updated automatically. To check for updates now, run " +
			colour.Cmd("fk team fetch") + "\n\n")

		out.Print(table.FormatKeyTablePrimaryInstruction(allKeysWithWarnings))
	}

	return 0
}

func printRequests() exitCode {
	requestsToJoinTeams, err := user.RequestsToJoinTeams()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to load requests to join teams", nil, err))
		return 1
	}

	allKeysWithWarnings := []table.KeyWithWarnings{}
	for _, request := range requestsToJoinTeams {
		printHeader(request.TeamName)

		key, err := loadPgpKey(request.Fingerprint)
		if err != nil {
			out.Print(ui.FormatFailure(
				"Failed to load key associated with team "+request.TeamName,
				[]string{
					"Tried to load key " + request.Fingerprint.Hex(),
				},
				err,
			))
			return 1
		}

		keyWithWarnings := table.KeyWithWarnings{
			Key:      key,
			Warnings: status.GetKeyWarnings(*key, &Config),
		}

		allKeysWithWarnings = append(allKeysWithWarnings, keyWithWarnings)

		out.Print(table.FormatKeyTable([]table.KeyWithWarnings{keyWithWarnings}))

		printRequestHasntBeenApproved(request)
	}

	out.Print(table.FormatKeyTablePrimaryInstruction(allKeysWithWarnings))

	return 0
}

func printOrphanedKeys() exitCode {
	orphanedFingerprints, err := user.OrphanedFingerprints()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to load keys", nil, err))
		return 1
	}

	keysWithWarnings := []table.KeyWithWarnings{}

	for _, fingerprint := range orphanedFingerprints {
		key, err := loadPgpKey(fingerprint)
		if err != nil {
			out.Print(ui.FormatFailure(
				"Failed to load key",
				[]string{
					"Tried to load key " + fingerprint.Hex(),
				},
				err,
			))
			return 1
		}

		keyWithWarnings := table.KeyWithWarnings{
			Key:      key,
			Warnings: status.GetKeyWarnings(*key, &Config),
		}
		keysWithWarnings = append(keysWithWarnings, keyWithWarnings)
	}

	out.Print(table.FormatKeyTable(keysWithWarnings))

	out.Print(ui.FormatWarning("You're not in a team", []string{
		"You've got " + humanize.Pluralize(len(keysWithWarnings), "key", "keys") +
			" but you're not a member of any teams.",
		"If your team is using Fluidkeys, ask your admin for an invite.",
		"You can create a new team by running " + colour.Cmd("fk team create"),
	}, nil))

	out.Print(table.FormatKeyTablePrimaryInstruction(keysWithWarnings))

	return 0
}
