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

// Memberships loads all teams, and loads my fingerprints, then returns the intersection.
// it returns 1 membership (team, fingerprint) for each key that's a member of a team
func (u User) Memberships() (teamMemberships []TeamMembership, err error) {
	myFingerprints, err := u.db.GetFingerprintsImportedIntoGnuPG()
	if err != nil {
		return nil, err
	}

	isMember := func(haystack []fpr.Fingerprint, needle fpr.Fingerprint) bool {
		for _, f := range haystack {
			if f == needle {
				return true
			}
		}
		return false
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

// TeamMembership records a connection between a Person and a Team. It's possible for several of
// a user's keys to all be in the same team.
type TeamMembership struct {
	Team team.Team
	Me   team.Person
}
