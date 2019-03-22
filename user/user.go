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

package user

import (
	"github.com/fluidkeys/fluidkeys/database"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/gofrs/uuid"
)

// User provides convenience functions around the database, config and teams subdirectory.
type User struct {
	fluidkeysDirectory string
	db                 *database.Database
}

// New initializes a User
func New(fluidkeysDirectory string, db *database.Database) *User {
	return &User{
		fluidkeysDirectory: fluidkeysDirectory,
		db:                 db,
	}
}

// GroupedMemberships loads all the teams, loads my fingerprints then returns the intersections
// grouped by the team uuid.
func (u User) GroupedMemberships() (groupedMemberships []GroupedMembership, err error) {
	myFingerprints, err := u.db.GetFingerprintsImportedIntoGnuPG()
	if err != nil {
		return nil, err
	}

	allTeams, err := team.LoadTeams(u.fluidkeysDirectory)
	if err != nil {
		return nil, err
	}

	for _, t := range allTeams {
		teamMemberships := []TeamMembership{}
		for _, person := range t.People {
			if isMember(myFingerprints, person.Fingerprint) {
				teamMemberships = append(
					teamMemberships,
					TeamMembership{
						Team: t,
						Me:   person,
					},
				)
			}
		}
		if len(teamMemberships) > 0 {
			groupedMemberships = append(
				groupedMemberships,
				GroupedMembership{
					Team:        t,
					Memberships: teamMemberships,
				},
			)
		}
	}
	return groupedMemberships, nil
}

// Memberships loads all teams, and loads my fingerprints, then returns the intersection.
// it returns 1 membership (team, fingerprint) for each key that's a member of a team
func (u User) Memberships() (teamMemberships []TeamMembership, err error) {
	myFingerprints, err := u.db.GetFingerprintsImportedIntoGnuPG()
	if err != nil {
		return nil, err
	}

	allTeams, err := team.LoadTeams(u.fluidkeysDirectory)
	if err != nil {
		return nil, err
	}

	for _, t := range allTeams {
		for _, person := range t.People {
			if isMember(myFingerprints, person.Fingerprint) {
				teamMemberships = append(
					teamMemberships,
					TeamMembership{
						Team: t,
						Me:   person,
					},
				)
			}
		}

	}
	return teamMemberships, nil
}

// IsInTeam returns true if *any* of the users keys are in the team with the given UUID.
func (u User) IsInTeam(teamUUID uuid.UUID) (isInTeam bool, theTeam *team.Team, err error) {
	memberships, err := u.Memberships()
	if err != nil {
		return false, nil, err
	}
	for _, membership := range memberships {
		if membership.Team.UUID == teamUUID {
			return true, &membership.Team, nil
		}
	}
	return false, nil, nil
}

// RequestsToJoinTeams loads all requests, and loads my fingerprints, then returns the intersection.
// it returns 1 team.RequestToJoinTeam for each key that's a member of a team
func (u User) RequestsToJoinTeams() (teamRequests []team.RequestToJoinTeam, err error) {
	myFingerprints, err := u.db.GetFingerprintsImportedIntoGnuPG()
	if err != nil {
		return nil, err
	}

	allRequests, err := u.db.GetRequestsToJoinTeams()
	if err != nil {
		return nil, err
	}

	for _, r := range allRequests {
		if isMember(myFingerprints, r.Fingerprint) {
			teamRequests = append(
				teamRequests,
				r,
			)
		}
	}

	return teamRequests, nil
}

// OrphanedFingerprints loads all fingerprints and returns any that aren't associated with a team
// nor a request to join a team
func (u User) OrphanedFingerprints() (orphanedFingerprints []fpr.Fingerprint, err error) {
	myFingerprints, err := u.db.GetFingerprintsImportedIntoGnuPG()
	if err != nil {
		return nil, err
	}

	requests, err := u.RequestsToJoinTeams()
	if err != nil {
		return nil, err
	}
	memberships, err := u.Memberships()
	if err != nil {
		return nil, err
	}

	for _, fingerprint := range myFingerprints {
		if fingerprintHasRequest(fingerprint, requests) {
			continue
		}
		if fingerprintHasMembership(fingerprint, memberships) {
			continue
		}
		orphanedFingerprints = append(orphanedFingerprints, fingerprint)
	}

	return orphanedFingerprints, nil
}

func fingerprintHasRequest(fingerprint fpr.Fingerprint, requests []team.RequestToJoinTeam) bool {
	for _, r := range requests {
		if r.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

func fingerprintHasMembership(fingerprint fpr.Fingerprint, memberships []TeamMembership) bool {
	for _, m := range memberships {
		if m.Me.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// TeamMembership records a connection between a Person and a Team. It's possible for several of
// a user's keys to all be in the same team.
type TeamMembership struct {
	Team team.Team
	Me   team.Person
}

type GroupedMembership struct {
	Team        team.Team
	Memberships []TeamMembership
}

func isMember(haystack []fpr.Fingerprint, needle fpr.Fingerprint) bool {
	for _, f := range haystack {
		if f == needle {
			return true
		}
	}
	return false
}
