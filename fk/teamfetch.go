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

	"github.com/fluidkeys/fluidkeys/apiclient"
	"github.com/fluidkeys/fluidkeys/colour"
	fp "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/fluidkeys/fluidkeys/ui"
)

func teamFetch(unattended bool) exitCode {
	sawError := false

	if err := processRequestsToJoinTeam(unattended); err != nil {
		// don't output anything: the function does that itself
		sawError = true
	}

	memberships, err := user.Memberships()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to list teams", nil, err))
		return 1
	}

	for i := range memberships {
		if err := doUpdateTeam(&memberships[i].Team, &memberships[i].Me, unattended); err != nil {
			sawError = true
		}
	}

	if sawError {
		out.Print("\n")
		printFailed("Encountered errors while syncing.\n")
		return 1
	}
	return 0
}

func doUpdateTeam(myTeam *team.Team, me *team.Person, unattended bool) (err error) {
	printHeader(myTeam.Name)

	var updatedTeam *team.Team
	if updatedTeam, err = fetchAndUpdateRoster(*myTeam, *me, unattended); err != nil {
		out.Print(ui.FormatWarning("Failed to check team for updates", []string{}, err))
		return err
	}
	myTeam = updatedTeam // move myTeam pointer to updatedTeam

	if err := fetchAndCertifyTeamKeys(*myTeam, *me, unattended); err != nil {
		out.Print(ui.FormatWarning("Error fetching team keys", nil, err))
		return err
	}

	out.Print(ui.FormatSuccess(
		successfullyFetchedKeysHeadline,
		[]string{
			"You have successfully fetched everyone's key in " + myTeam.Name + ".",
			"This means that you can now start sending and receiving secrets and",
			"using other GnuPG powered tools together.",
		},
	))
	return nil
}

func formatYouRequestedToJoin(request team.RequestToJoinTeam) string {
	return "You requested to join " + request.TeamName + " " +
		humanize.RoughDuration(time.Now().Sub(request.RequestedAt)) + " ago."
}

// fetchAndUpdateRoster fetches any update to the team roster and saves it back to disk.
// if alwaysDownload is false, only check the roster if we last checked it more than 24 hours ago
func fetchAndUpdateRoster(t team.Team, me team.Person, unattended bool) (
	updatedTeam *team.Team, err error) {

	alwaysDownload := !unattended

	// TODO: download the updated roster and handle the case where we're forbidden, as it
	// means we're no longer in the team.

	if !alwaysDownload {
		if stale, err := db.IsOlderThan(
			"fetch", t, time.Duration(24)*time.Hour, time.Now()); err != nil {

			return nil, fmt.Errorf("failed to check when team was last updated: %v", err)

		} else if !stale {
			log.Printf("skipping check for updates to roster for %s (fetched recently)", t.Name)
			return &t, nil // we checked for updates recently. nothing to do.
		}
	}

	roster, signature, err := api.GetTeamRoster(t.UUID, me.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("error downloading team roster: %v", err)
	}

	if originalRoster, _ := t.Roster(); originalRoster == roster {
		log.Printf("no change to roster, nothing to do.")
		db.RecordLast("fetch", t, time.Now())
		return &t, nil // no change to roster. nothing to do.
	}

	adminKeys, err := fetchAdminPublicKeys(t)
	if err != nil {
		return nil, fmt.Errorf("error getting team admin public keys: %v", err)
	}

	if err := team.VerifyRoster(roster, signature, adminKeys); err != nil {
		return nil, fmt.Errorf("couldn't validate signature on updated roster: %v", err)
	}
	log.Printf("new roster verified OK")

	teamSubdir, err := team.Directory(t, fluidkeysDirectory)
	if err != nil {
		return nil, err
	}

	saver := team.RosterSaver{Directory: teamSubdir}
	if err := saver.Save(roster, signature); err != nil {
		return nil, err
	}

	db.RecordLast("fetch", t, time.Now())

	updatedTeam, err = team.Load(roster, signature)
	if err != nil {
		return nil, err
	}
	return updatedTeam, nil
}

// fetchAndCertifyTeamKeys fetches each key listed in the team and locally signs them in GnuPG
// if `alwaysDownload` is false, it will only try to fetch keys every 24 hours, otherwise it'll
// check every time.
func fetchAndCertifyTeamKeys(
	t team.Team, me team.Person, unattended bool) (err error) {

	alwaysDownload := !unattended

	out.Print("Fetching and signing keys for other members of " + t.Name + ":\n\n")

	for _, person := range t.People {
		if person == me {
			continue
		}

		if !alwaysDownload {
			if stale, err := db.IsOlderThan("fetch", person.Fingerprint,
				time.Duration(24)*time.Hour, time.Now()); err != nil {
				return err
			} else if !stale {
				ui.PrintCheckboxSkipped(person.Email + " skipped: fetched recently")
				continue
			}
		}

		var theirKey *pgpkey.PgpKey

		err = ui.RunWithCheckboxes(person.Email+": fetch key", func() error {
			theirKey, err = api.GetPublicKeyByFingerprint(person.Fingerprint)

			if err != nil && err == apiclient.ErrPublicKeyNotFound {
				log.Print(err)
				return fmt.Errorf("Couldn't find key")
			} else if err != nil {
				log.Print(err)
				return fmt.Errorf("Got error from Fluidkeys server")
			}
			return nil
		})

		err = ui.RunWithCheckboxes(person.Email+": sign key", func() error {

			if !alreadyCertified(person.Email, person.Fingerprint, me.Fingerprint) {
				unlockedKey, err := getUnlockedKey(me.Fingerprint, unattended)
				if err != nil {
					out.Print(ui.FormatFailure(
						"Failed to unlock key to sign key", []string{
							"Signing (or certifying) a key requires an unlocked key.",
						}, err))
					return err
				}

				if err := theirKey.CertifyEmail(person.Email, unlockedKey, time.Now()); err != nil {
					log.Print(err)
					return fmt.Errorf("Failed to sign key: %v", err)
				}
				recordCertified(person.Email, person.Fingerprint, unlockedKey.Fingerprint())

			} else {
				log.Printf("key %s already certified by %s, not certifying again",
					person.Fingerprint.Hex(), me.Fingerprint.Hex())
				return ui.SkipThisAction
			}
			return nil
		})

		err = ui.RunWithCheckboxes(person.Email+": import into gpg", func() error {
			armoredKey, err := theirKey.Armor()
			if err != nil {
				log.Print(err)
				return fmt.Errorf("failed to ASCII armor key")
			}

			err = gpg.ImportArmoredKey(armoredKey)
			if err != nil {
				log.Print(err)
				return fmt.Errorf("Failed to import key into gpg")
			}
			db.RecordLast("fetch", theirKey.Fingerprint(), time.Now())

			return nil
		})
		// keep trying subsequent keys even if we hit an error.
	}
	out.Print("\n")
	return err
}

// emailKeyAndCertifier represents a combination of email (from UID), key, and certifier key.
// This is used to record in the database that we've already certified a UID.
// Caution: renaming this struct will invalidate any log entries.
type emailKeyAndCertifier struct {
	key       fp.Fingerprint
	email     string
	certifier fp.Fingerprint
}

func (k emailKeyAndCertifier) String() string {
	return fmt.Sprintf("%s-%s-by-%s", k.email, k.key.Uri(), k.certifier.Uri())
}

func alreadyCertified(email string, key, certifiedBy fp.Fingerprint) bool {
	record := emailKeyAndCertifier{
		email:     email,
		key:       key,
		certifier: certifiedBy,
	}

	timeCertified, err := db.GetLast("certify", record)
	if err != nil {
		log.Printf("error calling db.GetLast(\"certify\", %v): %v", record, err)
		return false
	}

	return !timeCertified.IsZero()
}

func recordCertified(email string, key fp.Fingerprint, certifiedBy fp.Fingerprint) {
	record := emailKeyAndCertifier{
		email:     email,
		key:       key,
		certifier: certifiedBy,
	}

	err := db.RecordLast("certify", record, time.Now())
	if err != nil {
		log.Printf("error calling db.RecordLast(\"certify\", %v, now): %v", record, err)
	}
}

func processRequestsToJoinTeam(unattended bool) (returnError error) {
	requestsToJoinTeams, err := user.RequestsToJoinTeams()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to get requests to join teams", nil, err))
		return err
	}

	// TODO: decide whether to process requests in cron mode

	for _, request := range requestsToJoinTeams {
		// TODO: check if I'm already in the team

		if time.Now().Sub(request.RequestedAt) > time.Duration(7*24)*time.Hour {
			out.Print(ui.FormatWarning(
				"Your request to join "+request.TeamName+" has expired",
				[]string{
					formatYouRequestedToJoin(request) + " The admin hasn't approved the ",
					"request, so it has expired.",
					"",
					"You can apply to join the team again by runnning ",
					colour.Cmd("fk team apply " + request.TeamUUID.String()),
				},
				nil,
			))
			db.DeleteRequestToJoinTeam(request.TeamUUID, request.Fingerprint)
			returnError = err // treat this as an error to draw attention to it in e.g. cron
			continue
		}

		roster, signature, err := api.GetTeamRoster(request.TeamUUID, request.Fingerprint)

		if err == apiclient.ErrForbidden {
			printRequestHasntBeenApproved(request)
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

		err = db.DeleteRequestToJoinTeam(request.TeamUUID, request.Fingerprint)
		if err != nil {
			out.Print(ui.FormatFailure("Error deleting request to join team", nil, err))
			returnError = err
			continue
		}
	}
	return returnError
}

func printRequestHasntBeenApproved(request team.RequestToJoinTeam) {
	out.Print(ui.FormatInfo(
		"Your request to join "+request.TeamName+" hasn't been approved",
		[]string{
			formatYouRequestedToJoin(request) + " The admin hasn't approved this",
			"request yet.",
		}),
	)
}

// unlockedKeyCache is used to store unlocked keys: don't unlock them more than once
// TODO: there's a good case for a new package or file with all these (similar) kind of helpers,
// they shouldn't all be living in these command files.
var unlockedKeyCache = map[fp.Fingerprint]*pgpkey.PgpKey{}

func getUnlockedKey(fingerprint fp.Fingerprint, unattended bool) (*pgpkey.PgpKey, error) {
	if key, ok := unlockedKeyCache[fingerprint]; ok {
		return key, nil
	}

	key, err := loadPgpKey(fingerprint)
	if err != nil {
		return nil, err
	}

	var prompter promptForPasswordInterface
	if unattended {
		// if we're in unattended mode and we don't have a password, we can't prompt for it, so
		// we fail instead.
		prompter = &alwaysFailPasswordPrompter{}
	} else {
		prompter = &interactivePasswordPrompter{}
	}

	unlockedKey, _, err := getDecryptedPrivateKeyAndPassword(key, prompter)
	if err != nil {
		return nil, err
	}

	unlockedKeyCache[fingerprint] = unlockedKey
	return unlockedKey, nil
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

	if key, err = api.GetPublicKeyByFingerprint(fingerprint); err != nil {
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
