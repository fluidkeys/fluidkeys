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
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/fluidkeys/fluidkeys/ui"
	userpackage "github.com/fluidkeys/fluidkeys/user"
)

func teamAuthorize() exitCode {
	allMemberships, err := user.Memberships()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to list teams", nil, err))
		return 1
	}

	adminMemberships := filterByAdmin(allMemberships)

	switch len(adminMemberships) {
	case 0:
		out.Print(ui.FormatFailure("You aren't an admin of any teams", nil, nil))
		return 1

	case 1:
		myTeam := adminMemberships[0].Team
		me := adminMemberships[0].Me

		printHeader("Authorize requests to join " + myTeam.Name)

		requests, err := api.ListRequestsToJoinTeam(myTeam.UUID, me.Fingerprint)
		if err != nil {
			out.Print(ui.FormatFailure("Error getting requests", nil, err))
			return 1
		}
		if len(requests) == 0 {
			out.Print("No requests to join " + myTeam.Name + "\n")
			return 0
		}

		out.Print(ui.FormatInfo(
			"Authorizing a key adds it to the team roster",
			[]string{
				"By authorizing a key, everyone in your team will fetch and trust that key.",
				"",
				"Your team should have sent you verification details.",
				"Check the key and email below match the verification details you've received.",
			},
		))

		approvedRequests, deleteRequests := reviewRequests(requests, myTeam)

		if len(approvedRequests) > 0 {
			for _, request := range approvedRequests {
				myTeam.UpsertPerson(
					team.Person{
						Email:       request.Email,
						Fingerprint: request.Fingerprint,
						IsAdmin:     false,
					})
			}

			printHeader("Sign and upload team roster")

			out.Print("The team roster is a signed file that defines who is in the team.\n\n")

			if err := promptAndSignAndUploadRoster(myTeam, me.Fingerprint); err != nil {
				out.Print(ui.FormatFailure("Failed to sign and upload roster", nil, err))
				return 1
			}

			if err := fetchAndCertifyTeamKeys(myTeam, me, false); err != nil {
				out.Print(ui.FormatWarning("Error fetching team keys", nil, err))
				return 1
			}
		}

		seenError := false

		for _, request := range deleteRequests {
			if err = api.DeleteRequestToJoinTeam(myTeam.UUID, request.UUID); err != nil {
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
	approvedRequests []team.RequestToJoinTeam, deleteRequests []team.RequestToJoinTeam) {

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
				deleteRequests = append(deleteRequests, request)
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

		addToTeam := prompter.promptYesNo(
			"Authorize "+request.Email+" now? (type n to decide later)", "", nil,
		)

		if addToTeam {
			approvedRequests = append(approvedRequests, request)
			deleteRequests = append(deleteRequests)
		} else {
			out.Print(ui.FormatWarning("Reject this request?",
				[]string{
					"If the verification details you've received from " + request.Email,
					"don't match, answer " + colour.Info("y") + " to reject the request.",
					"",
					"If you haven't received the verification details, answer " +
						colour.Info("n") + " and",
					"ask them to apply to join the team again.",
				}, nil))

			if prompter.promptYesNo("Reject the request?", "n", nil) {
				deleteRequests = append(deleteRequests, request)
			}
		}
	}

	return approvedRequests, deleteRequests
}

func filterByAdmin(memberships []userpackage.TeamMembership) (
	adminMemberships []userpackage.TeamMembership) {

	for _, membership := range memberships {
		if membership.Me.IsAdmin {
			adminMemberships = append(adminMemberships, membership)
		}
	}

	return adminMemberships
}
