package database

import (
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/fluidkeys/fluidkeys/testhelpers"
	"github.com/gofrs/uuid"
)

func TestRecordFingerprintImportedIntoGnuPG(t *testing.T) {

	t.Run("record works to an empty database", func(t *testing.T) {
		fingerprint := exampleFingerprintA
		database := New(testhelpers.Maketemp(t))
		err := database.RecordFingerprintImportedIntoGnuPG(fingerprint)
		assert.NoError(t, err)

		importedFingerprints, err := database.GetFingerprintsImportedIntoGnuPG()
		assertContainsFingerprint(t, importedFingerprints, fingerprint)
	})

	t.Run("record appends a new key to a database with key ids already stored", func(t *testing.T) {
		existingFingerprint := exampleFingerprintA
		newFingerprint := exampleFingerprintB
		database := New(testhelpers.Maketemp(t))

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
		database := New(testhelpers.Maketemp(t))

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
		database := New(testhelpers.Maketemp(t))
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

	request1 := team.RequestToJoinTeam{
		TeamUUID:    uuid.Must(uuid.NewV4()),
		TeamName:    "Example",
		Fingerprint: fingerprint,
		RequestedAt: now,
	}

	request2 := team.RequestToJoinTeam{
		TeamUUID:    uuid.Must(uuid.NewV4()),
		TeamName:    "Example",
		Fingerprint: exampledata.ExampleFingerprint3,
		RequestedAt: later,
	}

	t.Run("record works to an empty database", func(t *testing.T) {
		database := New(testhelpers.Maketemp(t))
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

		database := New(testhelpers.Maketemp(t))

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

	t.Run("record deduplicates selecting oldest requests for team & fingerprint", func(t *testing.T) {
		database := New(testhelpers.Maketemp(t))

		dupeReq := request1
		dupeReq.RequestedAt = later // older one should get dropped

		addRequestToJoinToDatabase(t, request1, database)
		addRequestToJoinToDatabase(t, dupeReq, database)

		t.Run("and we can read back a matching request ", func(t *testing.T) {
			gotRequests, err := database.GetRequestsToJoinTeams()
			assert.NoError(t, err)

			expectedRequests := []team.RequestToJoinTeam{request1}
			assert.Equal(t, expectedRequests, gotRequests)
		})
	})

	t.Run("doesn't overwrite keys imported into gnupg when recording a request to join a team", func(t *testing.T) {
		fingerprint := exampleFingerprintA
		database := New(testhelpers.Maketemp(t))
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

	newestReq := team.RequestToJoinTeam{
		TeamUUID:    uuid.Must(uuid.NewV4()),
		Fingerprint: fingerprint,
		RequestedAt: later,
	}

	oldestReq := team.RequestToJoinTeam{
		TeamUUID:    newestReq.TeamUUID,
		Fingerprint: fingerprint,
		RequestedAt: now,
	}

	anotherReq := team.RequestToJoinTeam{
		TeamUUID:    uuid.Must(uuid.NewV4()),
		Fingerprint: fingerprint,
		RequestedAt: evenLater,
	}

	t.Run("get requests returns de-duplicated requests", func(t *testing.T) {
		database := New(testhelpers.Maketemp(t))

		addRequestToJoinToDatabase(t, newestReq, database)
		addRequestToJoinToDatabase(t, oldestReq, database)
		addRequestToJoinToDatabase(t, anotherReq, database)

		gotRequests, err := database.GetRequestsToJoinTeams()
		assert.NoError(t, err)

		expectedRequests := []team.RequestToJoinTeam{oldestReq, anotherReq}
		assert.Equal(t, len(expectedRequests), len(gotRequests))
		assert.Equal(t, expectedRequests, gotRequests)
	})

	t.Run("returns oldest when newest was inserted first", func(t *testing.T) {
		database := New(testhelpers.Maketemp(t))
		addRequestToJoinToDatabase(t, newestReq, database)
		addRequestToJoinToDatabase(t, oldestReq, database)

		gotRequests, err := database.GetRequestsToJoinTeams()
		assert.NoError(t, err)

		expectedRequests := []team.RequestToJoinTeam{oldestReq}
		assert.Equal(t, len(expectedRequests), len(gotRequests))
		assert.Equal(t, expectedRequests, gotRequests)
	})

	t.Run("returns oldest when oldest was inserted first", func(t *testing.T) {
		database := New(testhelpers.Maketemp(t))

		addRequestToJoinToDatabase(t, oldestReq, database)
		addRequestToJoinToDatabase(t, newestReq, database)

		gotRequests, err := database.GetRequestsToJoinTeams()
		assert.NoError(t, err)

		expectedRequests := []team.RequestToJoinTeam{oldestReq}
		assert.Equal(t, len(expectedRequests), len(gotRequests))
		assert.Equal(t, expectedRequests, gotRequests)
	})

}

func TestDeleteRequestToJoinTeam(t *testing.T) {

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
		RequestedAt: later,                           // later than req3 so it sorts consistently
	}

	database := New(testhelpers.Maketemp(t))

	t.Run("set up the database ", func(t *testing.T) {
		addRequestToJoinToDatabase(t, req1, database)
		addRequestToJoinToDatabase(t, req2, database)
		addRequestToJoinToDatabase(t, req3, database)
		addRequestToJoinToDatabase(t, req4, database)
	})

	t.Run("deletes all requests matching the team UUID and fingerprint", func(t *testing.T) {
		assert.NoError(t, database.DeleteRequestToJoinTeam(req1.TeamUUID, req1.Fingerprint))

		gotRequests, err := database.GetRequestsToJoinTeams()
		assert.NoError(t, err)

		expectedRequests := []team.RequestToJoinTeam{req3, req4}
		assert.Equal(t, expectedRequests, gotRequests)
	})
}

func TestGetExistingRequestToJoinTeam(t *testing.T) {
	now := time.Date(2019, 6, 20, 16, 35, 0, 0, time.UTC)

	team1UUID := uuid.Must(uuid.NewV4())

	request1 := team.RequestToJoinTeam{
		TeamUUID:    team1UUID,
		Fingerprint: exampleFingerprintA,
		RequestedAt: now,
	}

	request1Dupe := team.RequestToJoinTeam{
		TeamUUID:    team1UUID,
		Fingerprint: exampleFingerprintA,
		RequestedAt: later,
	}

	request2 := team.RequestToJoinTeam{
		TeamUUID:    team1UUID,
		Fingerprint: exampleFingerprintB,
		RequestedAt: now,
	}

	team2UUID := uuid.Must(uuid.NewV4())

	request3 := team.RequestToJoinTeam{
		TeamUUID:    team2UUID,
		Fingerprint: exampleFingerprintA,
		RequestedAt: now,
	}

	t.Run("gets the earliest request for matching teamUUID and fingerprint", func(t *testing.T) {
		database := New(testhelpers.Maketemp(t))

		addRequestToJoinToDatabase(t, request1, database)
		addRequestToJoinToDatabase(t, request1Dupe, database)
		addRequestToJoinToDatabase(t, request2, database)
		addRequestToJoinToDatabase(t, request3, database)

		gotRequest, err := database.GetExistingRequestToJoinTeam(team1UUID, exampleFingerprintA)
		assert.NoError(t, err)
		assert.Equal(t, request1, *gotRequest)
	})

	t.Run("doesn't get error when request can't be found", func(t *testing.T) {
		database := New(testhelpers.Maketemp(t))

		addRequestToJoinToDatabase(t, request1, database)

		gotRequest, err := database.GetExistingRequestToJoinTeam(
			uuid.Must(uuid.NewV4()),
			exampleFingerprintA,
		)
		assert.NoError(t, err)
		if gotRequest != nil {
			t.Fatalf("expected gotRequest to be nil, but it isn't")
		}
	})
}

func TestUpdated(t *testing.T) {
	now := time.Date(2019, 6, 20, 16, 35, 0, 0, time.UTC)
	later := now.Add(time.Duration(6) * time.Hour)

	t.Run("fingerprints", func(t *testing.T) {
		database := New(testhelpers.Maketemp(t))

		fingerprint := exampledata.ExampleFingerprint2

		t.Run("record to an empty database", func(t *testing.T) {
			err := database.RecordLast("fetch", fingerprint, now)
			assert.NoError(t, err)
		})

		t.Run("can get last updated time", func(t *testing.T) {
			got, err := database.GetLast("fetch", fingerprint)
			assert.NoError(t, err)
			assert.Equal(t, now, got)
		})

		t.Run("pointers and values are handled the same", func(t *testing.T) {
			got, err := database.GetLast("fetch", &fingerprint)
			assert.NoError(t, err)
			assert.Equal(t, now, got)
		})

		t.Run("record updates the previously time", func(t *testing.T) {
			err := database.RecordLast("fetch", fingerprint, later)
			assert.NoError(t, err)

			got, err := database.GetLast("fetch", fingerprint)
			assert.NoError(t, err)
			assert.Equal(t, later, got)
		})

		t.Run("a second value records it's own time", func(t *testing.T) {
			fingerprint2 := exampledata.ExampleFingerprint3
			now := time.Date(2019, 6, 20, 16, 35, 0, 0, time.UTC)

			err := database.RecordLast("fetch", fingerprint2, now)
			assert.NoError(t, err)

			got, err := database.GetLast("fetch", fingerprint)
			assert.NoError(t, err)
			assert.Equal(t, later, got)

			got, err = database.GetLast("fetch", fingerprint2)
			assert.NoError(t, err)
			assert.Equal(t, now, got)
		})

		t.Run("keys are handled the same", func(t *testing.T) {
			err := database.RecordLast("fetch", fingerprint, now)

			key, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey2)
			assert.NoError(t, err)
			err = database.RecordLast("fetch", key, later)
			assert.NoError(t, err)

			got, err := database.GetLast("fetch", fingerprint)
			assert.NoError(t, err)
			assert.Equal(t, later, got)
		})

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

var (
	now       = time.Date(2019, 6, 20, 16, 35, 0, 0, time.UTC)
	later     = now.Add(time.Duration(1) * time.Hour)
	evenLater = now.Add(time.Duration(2) * time.Hour)
)

var exampleFingerprintA = fpr.MustParse("AAAA AAAA AAAA AAAA AAAA  AAAA AAAA AAAA AAAA AAAA")
var exampleFingerprintB = fpr.MustParse("BBBB BBBB BBBB BBBB BBBB  BBBB BBBB BBBB BBBB BBBB")
var exampleFingerprintC = fpr.MustParse("CCCC CCCC CCCC CCCC CCCC  CCCC CCCC CCCC CCCC CCCC")

var exampleKeyImportedMessageA = KeyImportedIntoGnuPGMessage{Fingerprint: exampleFingerprintA}
var exampleKeyImportedMessageB = KeyImportedIntoGnuPGMessage{Fingerprint: exampleFingerprintB}
var exampleKeyImportedMessageC = KeyImportedIntoGnuPGMessage{Fingerprint: exampleFingerprintC}
