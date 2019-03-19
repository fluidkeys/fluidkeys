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
	"log"
	"time"

	"github.com/fluidkeys/fluidkeys/api"
	"github.com/fluidkeys/fluidkeys/colour"
	fp "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/fluidkeys/fluidkeys/ui"
)

func teamFetch() exitCode {
	sawError := false

	myTeams, err := team.LoadTeams(fluidkeysDirectory)
	if err != nil {
		log.Panic(err)
	}

	for _, existingTeam := range myTeams {
		printHeader(existingTeam.Name)

		if err := fetchUpdatedRoster(existingTeam); err != nil {
			// TODO: download the updated roster and handle the case where we're forbidden, as it
			// means we're no longer in the team.
		}

		if err := fetchTeamKeys(existingTeam); err != nil {
			out.Print(ui.FormatWarning("Error fetching team keys", nil, err))
			sawError = true
			continue
		}

		out.Print(ui.FormatSuccess(
			successfullyFetchedKeysHeadline,
			[]string{
				"You have successfully fetched everyone's key in " +
					existingTeam.Name + ".",
			},
		))

	}

	newTeams, err := processRequestsToJoinTeam()
	if err != nil {
		// don't output anything: the function does that itself
		sawError = true
	}

	for _, newTeam := range newTeams {
		if err := fetchTeamKeys(newTeam); err != nil {
			out.Print(ui.FormatWarning("Error fetching team keys", nil, err))
			sawError = true
			continue
		}

		out.Print(ui.FormatSuccess(
			successfullyFetchedKeysHeadline,
			[]string{
				"You have successfully fetched everyone's key in " +
					newTeam.Name + ".",
				"This means that you can now start sending and receiving secrets and",
				"using other GnuPG powered tools together.",
			},
		))

	}

	if sawError {
		out.Print("\n")
		printFailed("Encountered errors while syncing.\n")
		return 1
	}
	return 0
}

func formatYouRequestedToJoin(request team.RequestToJoinTeam) string {
	return "You requested to join " + request.TeamName + " " +
		humanize.RoughDuration(time.Now().Sub(request.RequestedAt)) + " ago."
}

func fetchUpdatedRoster(t team.Team) (err error) {
	return fmt.Errorf("not implemented")
}

func fetchTeamKeys(t team.Team) (err error) {
	out.Print("Fetching keys for other members of " + t.Name + ":\n\n")

	for _, person := range t.People {
		err = ui.RunWithCheckboxes(person.Email, func() error {
			return getAndImportKeyToGpg(person.Fingerprint)
		})
		// keep trying subsequent keys even if we hit an error.
	}
	out.Print("\n")
	return err
}

func processRequestsToJoinTeam() (newTeams []team.Team, returnError error) {
	requestsToJoinTeams, err := db.GetRequestsToJoinTeams()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to get requests to join teams", nil, err))
		return nil, err
	}

	// TODO: decide whether to process requests in cron mode

	for _, request := range requestsToJoinTeams {
		printHeader(request.TeamName)
		// TODO: check if I'm already in the team

		if time.Now().Sub(request.RequestedAt) > time.Duration(7*24)*time.Hour {
			out.Print(ui.FormatWarning(
				"Your request to join "+request.TeamName+" has expired",
				[]string{
					formatYouRequestedToJoin(request) + " The admin hasn't approved the ",
					"request, so it has expired.",
					"",
					"You can request to join the team again by runnning ",
					colour.Cmd("fk team join " + request.TeamUUID.String()),
				},
				nil,
			))
			db.DeleteRequestToJoinTeam(request.TeamUUID, request.Fingerprint)
			returnError = err // treat this as an error to draw attention to it in e.g. cron
			continue
		}

		key, err := loadPgpKey(request.Fingerprint)
		if err != nil {
			out.Print(ui.FormatFailure("Failed to load requesting key", nil, err))
			returnError = err
			continue
		}

		passwordPrompter := interactivePasswordPrompter{}
		unlockedKey, _, err := getDecryptedPrivateKeyAndPassword(key, &passwordPrompter)
		if err != nil {
			out.Print(ui.FormatFailure("Failed to unlock private key", nil, err))
			returnError = err
			continue
		}

		roster, signature, err := client.GetTeamRoster(unlockedKey, request.TeamUUID)

		if err == api.ErrForbidden {
			out.Print(ui.FormatInfo(
				"Your request to join "+request.TeamName+" hasn't been approved",
				[]string{
					formatYouRequestedToJoin(request) + " The admin hasn't approved this",
					"request yet.",
				}),
			)
			continue // don't set returnError: this is an OK outcome
		} else if err != nil {
			out.Print(ui.FormatFailure("Failed to get team roster", nil, err))
			returnError = err
			continue
		}

		t, err := team.Load(roster, signature)
		if err != nil {
			out.Print(ui.FormatFailure("Failed to load team", nil, err))
			returnError = err
			continue
		}

		if err = verifyBrandNewRoster(*t, roster, signature); err != nil {
			out.Print(ui.FormatFailure(
				"Failed to verify team roster's cryptographic signature", nil, err,
			))
			returnError = err
			continue
		}

		teamSubdirectory, err := team.Directory(*t, fluidkeysDirectory)
		if err != nil {
			out.Print(ui.FormatFailure("Failed to get team subdirectory", nil, err))
			returnError = err
			continue
		}
		rosterWriter := team.RosterSaver{Directory: teamSubdirectory}
		err = rosterWriter.Save(roster, signature)

		if err != nil {
			out.Print(ui.FormatFailure("Failed to save team roster", nil, err))
			returnError = err
			continue
		}

		out.Print(ui.FormatSuccess(
			"Your request to join "+t.Name+" has been approved",
			[]string{
				formatYouRequestedToJoin(request) + " The admin has approved this",
				"request.",
			}))
		newTeams = append(newTeams, *t)
		err = db.DeleteRequestToJoinTeam(request.TeamUUID, request.Fingerprint)
		if err != nil {
			out.Print(ui.FormatFailure("Error deleting request to join team", nil, err))
			returnError = err
			continue
		}
	}
	return newTeams, returnError
}

func getAndImportKeyToGpg(fingerprint fp.Fingerprint) error {
	key, err := client.GetPublicKeyByFingerprint(fingerprint)

	if err != nil && err == api.ErrPublicKeyNotFound {
		log.Print(err)
		return fmt.Errorf("Couldn't find key")
	} else if err != nil {
		log.Print(err)
		return fmt.Errorf("Got error from Fluidkeys server")
	}

	armoredKey, err := key.Armor()
	if err != nil {
		log.Print(err)
		return fmt.Errorf("failed to ASCII armor key")
	}

	err = gpg.ImportArmoredKey(armoredKey)
	if err != nil {
		log.Print(err)
		return fmt.Errorf("Failed to import key into gpg")
	}
	return nil
}

func fetchAdminPublicKeys(t team.Team) (adminKeys []*pgpkey.PgpKey, err error) {
	for _, p := range t.Admins() {
		key, err := discoverPublicKey(p.Fingerprint)
		if err != nil {
			return nil, err
		}
		adminKeys = append(adminKeys, key)
	}
	return adminKeys, nil
}

func discoverPublicKey(fingerprint fp.Fingerprint) (key *pgpkey.PgpKey, err error) {
	if key, err := loadPgpKey(fingerprint); err != nil { // no error
		log.Printf("failed to find key %s in GnuPG: %v", fingerprint, err)
	} else {
		return key, nil
	}

	if key, err = client.GetPublicKeyByFingerprint(fingerprint); err != nil {
		log.Printf("failed to find key %s in API: %v", fingerprint, err)
	} else {
		return key, nil
	}

	return nil, fmt.Errorf("failed multiple attempts to find get public key for %s", fingerprint)
}

// verifyBrandNewRoster fetches the public keys of the admins in the team and verifies the roster
// against them.
func verifyBrandNewRoster(t team.Team, roster string, signature string) error {
	adminKeys, err := fetchAdminPublicKeys(t)
	if err != nil {
		return err
	}

	return team.VerifyRoster(roster, signature, adminKeys)
}

const (
	successfullyFetchedKeysHeadline = "Successfully fetched keys and imported them into GnuPG"
)
