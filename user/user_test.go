package user

import (
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/database"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/fluidkeys/fluidkeys/testhelpers"
	"github.com/gofrs/uuid"
)

func TestMemberships(t *testing.T) {
	fluidkeysDir := testhelpers.Maketemp(t) // fake fluidkeysDirectory
	db := database.New(fluidkeysDir)

	user := New(fluidkeysDir, &db)

	myFingerprint1 := exampledata.ExampleFingerprint2
	myFingerprint2 := exampledata.ExampleFingerprint3
	anotherFingerprint1 := exampledata.ExampleFingerprint4

	t.Run("returns team memberships", func(t *testing.T) {
		me1 := team.Person{
			Email:       "me1@example.com",
			Fingerprint: myFingerprint1,
			IsAdmin:     true,
		}
		me2 := team.Person{
			Email:       "me2@example.com",
			Fingerprint: myFingerprint2,
		}

		team1 := team.Team{
			Name: "Team 1",
			UUID: uuid.Must(uuid.NewV4()),
			People: []team.Person{
				me1,
				me2,
				{
					Email:       "another@example.com",
					Fingerprint: anotherFingerprint1,
				},
			},
		}

		team2 := team.Team{
			Name: "Team 2",
			UUID: uuid.Must(uuid.NewV4()),
			People: []team.Person{
				{
					Email:       "another@example.com",
					Fingerprint: anotherFingerprint1,
					IsAdmin:     true,
				},
			},
		}

		saveTeam(t, &team1, fluidkeysDir)
		saveTeam(t, &team2, fluidkeysDir)

		assert.NoError(t, db.RecordFingerprintImportedIntoGnuPG(myFingerprint1))
		assert.NoError(t, db.RecordFingerprintImportedIntoGnuPG(myFingerprint2))

		got, err := user.Memberships()

		assert.NoError(t, err)
		assert.Equal(t, []TeamMembership{
			{
				Team: team1,
				Me:   me1,
			},
			{
				Team: team1,
				Me:   me2,
			},
		}, got)
	})

}

func saveTeam(t *testing.T, theTeam *team.Team, fluidkeysDirectory string) {
	teamSubdir, err := team.Directory(*theTeam, fluidkeysDirectory)
	assert.NoError(t, err)

	saver := team.RosterSaver{Directory: teamSubdir}

	roster, err := theTeam.PreviewRoster()
	assert.NoError(t, err)
	saver.Save(roster, "fake signature")
}
