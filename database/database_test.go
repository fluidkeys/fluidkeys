package database

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/gofrs/uuid"
)

func TestRecordFingerprintImportedIntoGnuPG(t *testing.T) {

	t.Run("record works to an empty database", func(t *testing.T) {
		fingerprint := exampleFingerprintA
		database := New(makeTempDirectory(t))
		err := database.RecordFingerprintImportedIntoGnuPG(fingerprint)
		assert.NoError(t, err)

		importedFingerprints, err := database.GetFingerprintsImportedIntoGnuPG()
		assertContainsFingerprint(t, importedFingerprints, fingerprint)
	})

	t.Run("record appends a new key to a database with key ids already stored", func(t *testing.T) {
		existingFingerprint := exampleFingerprintA
		newFingerprint := exampleFingerprintB
		database := New(makeTempDirectory(t))

		err := database.RecordFingerprintImportedIntoGnuPG(existingFingerprint)
		assert.NoError(t, err)
		err = database.RecordFingerprintImportedIntoGnuPG(newFingerprint)
		assert.NoError(t, err)

		importedFingerprints, err := database.GetFingerprintsImportedIntoGnuPG()
		assertContainsFingerprint(t, importedFingerprints, existingFingerprint)
		assertContainsFingerprint(t, importedFingerprints, newFingerprint)
	})

	t.Run("doesn't duplicate key ids if trying to record a key that already is stored", func(t *testing.T) {
		fingerprint := exampleFingerprintA
		database := New(makeTempDirectory(t))

		err := database.RecordFingerprintImportedIntoGnuPG(fingerprint)
		assert.NoError(t, err)
		err = database.RecordFingerprintImportedIntoGnuPG(fingerprint)
		assert.NoError(t, err)

		importedFingerprints, err := database.GetFingerprintsImportedIntoGnuPG()
		if len(importedFingerprints) != 1 {
			t.Errorf("Expected 1 entry in slice, '%v'", importedFingerprints)
		}
	})
}

func TestGetFingerprintsImportedIntoGnuPG(t *testing.T) {

	t.Run("can read back fingerprint written to database", func(t *testing.T) {
		database := New(makeTempDirectory(t))
		fingerprint := exampleFingerprintA
		err := database.RecordFingerprintImportedIntoGnuPG(fingerprint)
		assert.NoError(t, err)

		importedFingerprints, err := database.GetFingerprintsImportedIntoGnuPG()
		assert.NoError(t, err)
		assertContainsFingerprint(t, importedFingerprints, fingerprint)
	})

}

func TestRecordRequestsToJoinTeamG(t *testing.T) {

	fingerprint := exampledata.ExampleFingerprint2
	now := time.Date(2019, 6, 20, 16, 35, 0, 0, time.UTC)
	later := now.Add(time.Duration(1) * time.Hour)

	request1 := team.RequestToJoinTeam{
		TeamUUID:    uuid.Must(uuid.NewV4()),
		TeamName:    "Example",
		UUID:        uuid.UUID{}, // empty *request* UUID, we don't store that
		Fingerprint: fingerprint,
		RequestedAt: now,
		Email:       "",
	}

	request2 := team.RequestToJoinTeam{
		TeamUUID:    uuid.Must(uuid.NewV4()),
		TeamName:    "Example",
		UUID:        uuid.UUID{}, // empty *request* UUID, we don't store that
		Fingerprint: exampledata.ExampleFingerprint3,
		RequestedAt: later,
		Email:       "",
	}

	t.Run("record works to an empty database", func(t *testing.T) {
		database := New(makeTempDirectory(t))
		err := database.RecordRequestToJoinTeam(
			request1.TeamUUID,
			request1.TeamName,
			request1.Fingerprint,
			request1.RequestedAt)

		assert.NoError(t, err)

		t.Run("and we can read back a matching request ", func(t *testing.T) {
			requestsToJoinTeams, err := database.GetRequestsToJoinTeams()
			assert.NoError(t, err)

			expectedRequest := request1
			assertContainsRequest(t, requestsToJoinTeams, expectedRequest)
		})

	})

	t.Run("record appends a new request to a database with requests already stored", func(t *testing.T) {

		database := New(makeTempDirectory(t))

		err := database.RecordRequestToJoinTeam(
			request1.TeamUUID,
			request1.TeamName,
			request1.Fingerprint,
			request1.RequestedAt,
		)
		assert.NoError(t, err)
		err = database.RecordRequestToJoinTeam(
			request2.TeamUUID,
			request1.TeamName,
			request2.Fingerprint,
			request2.RequestedAt,
		)
		assert.NoError(t, err)

		t.Run("and we can read back a matching request ", func(t *testing.T) {
			requestsToJoinTeams, err := database.GetRequestsToJoinTeams()
			assert.NoError(t, err)
			assertContainsRequest(t, requestsToJoinTeams, request1)
			assertContainsRequest(t, requestsToJoinTeams, request2)
		})
	})

	t.Run("doesn't overwrite keys imported into gnupg when recording a request to join a team", func(t *testing.T) {
		fingerprint := exampleFingerprintA
		database := New(makeTempDirectory(t))
		err := database.RecordFingerprintImportedIntoGnuPG(fingerprint)
		assert.NoError(t, err)

		err = database.RecordRequestToJoinTeam(
			request1.TeamUUID,
			request1.TeamName,
			request1.Fingerprint,
			request1.RequestedAt,
		)
		assert.NoError(t, err)

		importedFingerprints, err := database.GetFingerprintsImportedIntoGnuPG()
		assert.NoError(t, err)
		assertContainsFingerprint(t, importedFingerprints, fingerprint)
	})
}

func TestGetRequestsToJoinTeams(t *testing.T) {
	fingerprint := exampledata.ExampleFingerprint2
	now := time.Date(2019, 6, 20, 16, 35, 0, 0, time.UTC)

	request1 := team.RequestToJoinTeam{
		TeamUUID:    uuid.Must(uuid.NewV4()),
		UUID:        uuid.UUID{}, // empty *request* UUID, we don't store that
		Fingerprint: fingerprint,
		RequestedAt: now,
		Email:       "",
	}

	t.Run("can read back requests to join team written to database", func(t *testing.T) {
		database := New(makeTempDirectory(t))

		t.Run("set up the database ", func(t *testing.T) {
			err := database.RecordRequestToJoinTeam(
				request1.TeamUUID,
				request1.TeamName,
				request1.Fingerprint,
				request1.RequestedAt,
			)
			assert.NoError(t, err)
		})

		gotRequests, err := database.GetRequestsToJoinTeams()
		assert.NoError(t, err)
		assertContainsRequest(t, gotRequests, request1)
	})

}

func TestDeleteRequestToJoinTeam(t *testing.T) {
	now := time.Date(2019, 6, 20, 16, 35, 0, 0, time.UTC)
	later := now.Add(time.Duration(10) * time.Minute)

	req1 := team.RequestToJoinTeam{
		TeamUUID:    uuid.Must(uuid.NewV4()),
		Fingerprint: exampledata.ExampleFingerprint2,
		RequestedAt: now,
	}

	req2 := team.RequestToJoinTeam{
		TeamUUID:    req1.TeamUUID,
		Fingerprint: req1.Fingerprint,
		RequestedAt: later,
	}

	req3 := team.RequestToJoinTeam{
		TeamUUID:    req1.TeamUUID,
		Fingerprint: exampledata.ExampleFingerprint3, // same team, different fingerprint
		RequestedAt: now,
	}

	req4 := team.RequestToJoinTeam{
		TeamUUID:    uuid.Must(uuid.NewV4()),
		Fingerprint: exampledata.ExampleFingerprint3, // same fingerprint, different team
		RequestedAt: now,
	}

	database := New(makeTempDirectory(t))

	t.Run("set up the database ", func(t *testing.T) {
		assert.NoError(t, database.RecordRequestToJoinTeam(
			req1.TeamUUID, "", req1.Fingerprint, req1.RequestedAt,
		))

		assert.NoError(t, database.RecordRequestToJoinTeam(
			req2.TeamUUID, "", req2.Fingerprint, req2.RequestedAt,
		))

		assert.NoError(t, database.RecordRequestToJoinTeam(
			req3.TeamUUID, "", req3.Fingerprint, req3.RequestedAt,
		))

		assert.NoError(t, database.RecordRequestToJoinTeam(
			req4.TeamUUID, "", req4.Fingerprint, req4.RequestedAt,
		))

	})

	t.Run("deletes all requests matching the team UUID and fingerprint", func(t *testing.T) {
		assert.NoError(t, database.DeleteRequestToJoinTeam(req1.TeamUUID, req1.Fingerprint))

		gotRequests, err := database.GetRequestsToJoinTeams()
		assert.NoError(t, err)

		expectedRequests := []team.RequestToJoinTeam{req3, req4}
		assert.Equal(t, expectedRequests, gotRequests)
	})

}

func TestGetRequestsToJoinTeam(t *testing.T) {
	now := time.Date(2019, 6, 20, 16, 35, 0, 0, time.UTC)

	team1UUID := uuid.Must(uuid.NewV4())

	request1 := team.RequestToJoinTeam{
		TeamUUID:    team1UUID,
		UUID:        uuid.UUID{}, // empty *request* UUID, we don't store that
		Fingerprint: exampleFingerprintA,
		RequestedAt: now,
		Email:       "",
	}

	request2 := team.RequestToJoinTeam{
		TeamUUID:    team1UUID,
		UUID:        uuid.UUID{}, // empty *request* UUID, we don't store that
		Fingerprint: exampleFingerprintB,
		RequestedAt: now,
		Email:       "",
	}

	team2UUID := uuid.Must(uuid.NewV4())

	request3 := team.RequestToJoinTeam{
		TeamUUID:    team2UUID,
		UUID:        uuid.UUID{}, // empty *request* UUID, we don't store that
		Fingerprint: exampleFingerprintC,
		RequestedAt: now,
		Email:       "",
	}

	expectedRequests := []team.RequestToJoinTeam{request1, request2}

	t.Run("can read back requests to join a specific team", func(t *testing.T) {
		database := New(makeTempDirectory(t))

		addRequestToJoinToDatabase(t, request1, database)
		addRequestToJoinToDatabase(t, request2, database)
		addRequestToJoinToDatabase(t, request3, database)

		gotRequests, err := database.GetRequestsToJoinTeam(team1UUID)
		assert.NoError(t, err)
		assert.Equal(t, expectedRequests, gotRequests)
	})

}

func TestDeduplicateKeyImportedIntoGnuPGMessages(t *testing.T) {

	slice := []KeyImportedIntoGnuPGMessage{
		exampleKeyImportedMessageA,
		exampleKeyImportedMessageA,
		exampleKeyImportedMessageB,
		exampleKeyImportedMessageC,
	}

	got := deduplicateKeyImportedIntoGnuPGMessages(slice)
	want := []KeyImportedIntoGnuPGMessage{
		exampleKeyImportedMessageA,
		exampleKeyImportedMessageB,
		exampleKeyImportedMessageC,
	}

	if len(got) != len(want) {
		t.Errorf("Expected '%v' but got '%v'", want, got)
	}
}

func makeTempDirectory(t *testing.T) string {
	t.Helper()
	dir, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	return dir
}

func addRequestToJoinToDatabase(t *testing.T, request team.RequestToJoinTeam, database Database) {
	t.Helper()
	assert.NoError(t, database.RecordRequestToJoinTeam(
		request.TeamUUID,
		request.TeamName,
		request.Fingerprint,
		request.RequestedAt,
	))
}

func assertContainsFingerprint(t *testing.T, slice []fpr.Fingerprint, element fpr.Fingerprint) {
	t.Helper()
	if !containsFingerprint(slice, element) {
		t.Fatalf("Expected '%v' to contain '%v'", slice, element)
	}
}

func containsFingerprint(s []fpr.Fingerprint, e fpr.Fingerprint) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func assertContainsRequest(t *testing.T, slice []team.RequestToJoinTeam, element team.RequestToJoinTeam) {
	t.Helper()
	if !containsRequest(slice, element) {
		t.Fatalf("Expected '%v' to contain '%v'", slice, element)
	}
}

func containsRequest(s []team.RequestToJoinTeam, e team.RequestToJoinTeam) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

var exampleFingerprintA = fpr.MustParse("AAAA AAAA AAAA AAAA AAAA  AAAA AAAA AAAA AAAA AAAA")
var exampleFingerprintB = fpr.MustParse("BBBB BBBB BBBB BBBB BBBB  BBBB BBBB BBBB BBBB BBBB")
var exampleFingerprintC = fpr.MustParse("CCCC CCCC CCCC CCCC CCCC  CCCC CCCC CCCC CCCC CCCC")

var exampleKeyImportedMessageA = KeyImportedIntoGnuPGMessage{Fingerprint: exampleFingerprintA}
var exampleKeyImportedMessageB = KeyImportedIntoGnuPGMessage{Fingerprint: exampleFingerprintB}
var exampleKeyImportedMessageC = KeyImportedIntoGnuPGMessage{Fingerprint: exampleFingerprintC}
