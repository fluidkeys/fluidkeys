package user

import (
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/database"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/fluidkeys/fluidkeys/testhelpers"
	"github.com/gofrs/uuid"
)

func TestMembershipFunctions(t *testing.T) {
	fluidkeysDir := testhelpers.Maketemp(t) // fake fluidkeysDirectory
	db := database.New(fluidkeysDir)

	user := New(fluidkeysDir, &db)

	myFingerprint1 := exampledata.ExampleFingerprint2
	myFingerprint2 := exampledata.ExampleFingerprint3
	anotherFingerprint1 := exampledata.ExampleFingerprint4

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

	t.Run("Memberships", func(t *testing.T) {
		got, err := user.Memberships()

		assert.NoError(t, err)

		if len(got) != 2 {
			t.Fatalf("expected 2 team memberships, got %d: %v", len(got), got)
		}

		assert.Equal(t, team1.UUID, got[0].Team.UUID)
		assert.Equal(t, me1, got[0].Me)

		assert.Equal(t, team1.UUID, got[1].Team.UUID)
		assert.Equal(t, me2, got[1].Me)
	})

	t.Run("GroupedMemberships", func(t *testing.T) {
		got, err := user.GroupedMemberships()

		assert.NoError(t, err)

		if len(got) != 1 {
			t.Fatalf("expected 1 grouped memberships, got %d: %v", len(got), got)
		}

		assert.Equal(t, team1.UUID, got[0].Team.UUID)
		assert.Equal(t, me1, got[0].Memberships[0].Me)
		assert.Equal(t, me2, got[0].Memberships[1].Me)
	})

	t.Run("InTeam", func(t *testing.T) {
		t.Run("user is in team", func(t *testing.T) {
			gotIsInTeam, gotTeam, err := user.IsInTeam(team1.UUID)
			assert.NoError(t, err)

			t.Run("return value of isInTeam should be false", func(t *testing.T) {
				assert.Equal(t, true, gotIsInTeam)
			})

			t.Run("return value of theTeam should be pointer to correct team", func(t *testing.T) {
				if gotTeam == nil {
					t.Fatalf("got nil pointer for team")
				}
				assert.Equal(t, team1.UUID, gotTeam.UUID)
			})
		})

		t.Run("user is not in team", func(t *testing.T) {
			gotIsInTeam, gotTeam, err := user.IsInTeam(team2.UUID)
			assert.NoError(t, err)

			t.Run("return value of isInTeam should be false", func(t *testing.T) {
				assert.Equal(t, false, gotIsInTeam)
			})

			t.Run("return value of theTeam should be nil pointer", func(t *testing.T) {
				if gotTeam != nil {
					t.Fatalf("expected gotTeam to be nil, but it isn't")
				}
			})
		})
	})

}

func TestRequestFunctions(t *testing.T) {
	fluidkeysDir := testhelpers.Maketemp(t) // fake fluidkeysDirectory
	db := database.New(fluidkeysDir)

	now := time.Date(2018, 9, 24, 18, 0, 0, 0, time.UTC)
	later := now.Add(time.Duration(2) * time.Hour)

	user := New(fluidkeysDir, &db)

	myFingerprint := exampledata.ExampleFingerprint2
	myFingerprintNotInGPG := exampledata.ExampleFingerprint3

	assert.NoError(t, db.RecordFingerprintImportedIntoGnuPG(myFingerprint))

	team1 := team.Team{
		Name: "Team 1",
		UUID: uuid.Must(uuid.NewV4()),
	}

	assert.NoError(t, db.RecordRequestToJoinTeam(team1.UUID, team1.Name, myFingerprint, now))
	assert.NoError(t, db.RecordRequestToJoinTeam(team1.UUID, team1.Name, myFingerprintNotInGPG, later))

	t.Run("RequestsToJoinTeams", func(t *testing.T) {
		got, err := user.RequestsToJoinTeams()

		assert.NoError(t, err)

		if len(got) != 1 {
			t.Fatalf("expected 1 requests, got %d: %v", len(got), got)
		}

		assert.Equal(t, team1.UUID, got[0].TeamUUID)
		assert.Equal(t, myFingerprint, got[0].Fingerprint)
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
