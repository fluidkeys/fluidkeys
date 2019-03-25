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
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/status"
	"github.com/fluidkeys/fluidkeys/table"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/fluidkeys/fluidkeys/ui"
	userpackage "github.com/fluidkeys/fluidkeys/user"
)

func statusSubcommand(args docopt.Opts) exitCode {
	out.Print("\n")

	allKeysWithWarnings := []table.KeyWithWarnings{}

	groupedMemberships, err := user.GroupedMemberships()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to load team memberships", nil, err))
		return 1
	}
	membershipKeysWithWarnings, code := printMemberships(groupedMemberships)
	if code != 0 {
		return code
	}
	allKeysWithWarnings = append(allKeysWithWarnings, membershipKeysWithWarnings...)

	requestsToJoinTeams, err := user.RequestsToJoinTeams()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to load requests to join teams", nil, err))
		return 1
	}
	requestKeysWithWarnings, code := printRequests(requestsToJoinTeams)
	if code != 0 {
		return code
	}
	allKeysWithWarnings = append(allKeysWithWarnings, requestKeysWithWarnings...)

	orphanedFingerprints, err := user.OrphanedFingerprints()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to load keys", nil, err))
		return 1
	}
	orphanedKeysWithWarnings, code := printOrphanedKeys(orphanedFingerprints)
	if code != 0 {
		return code
	}
	allKeysWithWarnings = append(allKeysWithWarnings, orphanedKeysWithWarnings...)

	if len(groupedMemberships) == 0 {
		out.Print(ui.FormatWarning("You're not in a team", []string{
			"You've got " + humanize.Pluralize(len(orphanedFingerprints), "key", "keys") +
				" but you're not a member of any teams.",
			"If your team is using Fluidkeys, ask your admin for an invite.",
			"You can create a new team by running " + colour.Cmd("fk team create"),
		}, nil))
	}

	out.Print(table.FormatKeyTablePrimaryInstruction(allKeysWithWarnings))

	return 0
}

func printMemberships(groupedMemberships []userpackage.GroupedMembership) (
	membershipKeysWithWarnings []table.KeyWithWarnings, code exitCode) {

	for _, groupedMembership := range groupedMemberships {
		printHeader(groupedMembership.Team.Name)

		adminOfTeam := false

		teamKeysWithWarnings := []table.KeyWithWarnings{}

		for _, membership := range groupedMembership.Memberships {
			key, err := loadPgpKey(membership.Me.Fingerprint)
			if err != nil {
				out.Print(
					formatFailedToLoadKey(membership.Me.Fingerprint, membership.Team.Name, err),
				)
				return nil, 1
			}

			keyWithWarnings := table.KeyWithWarnings{
				Key:      key,
				Warnings: status.GetKeyWarnings(*key, &Config),
			}

			teamKeysWithWarnings = append(teamKeysWithWarnings, keyWithWarnings)
			membershipKeysWithWarnings = append(membershipKeysWithWarnings, keyWithWarnings)
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
				colour.Cmd("fk team apply " + groupedMembership.Team.UUID.String()),
			}))
		}

		out.Print("Team keys are updated automatically. To check for updates now, run " +
			colour.Cmd("fk team fetch") + "\n\n")
	}

	return membershipKeysWithWarnings, 0
}

func printRequests(requestsToJoinTeams []team.RequestToJoinTeam) (
	requestKeysWithWarnings []table.KeyWithWarnings, code exitCode) {

	for _, request := range requestsToJoinTeams {
		printHeader(request.TeamName)

		key, err := loadPgpKey(request.Fingerprint)
		if err != nil {
			out.Print(
				formatFailedToLoadKey(request.Fingerprint, request.TeamName, err),
			)
			return nil, 1
		}

		keyWithWarnings := table.KeyWithWarnings{
			Key:      key,
			Warnings: status.GetKeyWarnings(*key, &Config),
		}

		requestKeysWithWarnings = append(requestKeysWithWarnings, keyWithWarnings)

		out.Print(table.FormatKeyTable([]table.KeyWithWarnings{keyWithWarnings}))

		printRequestHasntBeenApproved(request)
	}

	return requestKeysWithWarnings, 0
}

func printOrphanedKeys(orphanedFingerprints []fpr.Fingerprint) (
	orphanedKeysWithWarnings []table.KeyWithWarnings, code exitCode) {

	if len(orphanedFingerprints) == 0 {
		return orphanedKeysWithWarnings, 0
	}

	printHeader("Keys that are not in a team")

	for _, fingerprint := range orphanedFingerprints {
		key, err := loadPgpKey(fingerprint)
		if err != nil {
			out.Print(
				formatFailedToLoadKey(fingerprint, "", err),
			)
			return nil, 1
		}
		keyWithWarnings := table.KeyWithWarnings{
			Key:      key,
			Warnings: status.GetKeyWarnings(*key, &Config),
		}
		orphanedKeysWithWarnings = append(orphanedKeysWithWarnings, keyWithWarnings)
	}

	out.Print(table.FormatKeyTable(orphanedKeysWithWarnings))
	return orphanedKeysWithWarnings, 0
}

func formatFailedToLoadKey(fingerprint fpr.Fingerprint, teamName string, err error) string {
	headline := ""
	if teamName == "" {
		headline = "Failed to load key"
	} else {
		headline = "Failed to load key associated with team " + teamName
	}

	return ui.FormatFailure(
		headline,
		[]string{
			"Tried to load key from GnuPG: " + fingerprint.Hex(),
			"",
			"If this key no longer exists, you can remove it from the `db.json` file",
			"in your Fluidkeys directory " + fluidkeysDirectory,
		},
		err,
	)
}
