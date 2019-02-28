package database

import (
	"io/ioutil"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/fingerprint"
)

func TestRecordFingerprintImportedIntoGnuPG(t *testing.T) {

	t.Run("record works to an empty database", func(t *testing.T) {
		fingerprint := exampleFingerprintA
		database := New(makeTempDirectory(t))
		err := database.RecordFingerprintImportedIntoGnuPG(fingerprint)
		assert.NoError(t, err)

		importedFingerprints, err := database.GetFingerprintsImportedIntoGnuPG()
		assertContains(t, importedFingerprints, fingerprint)
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
		assertContains(t, importedFingerprints, existingFingerprint)
		assertContains(t, importedFingerprints, newFingerprint)
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
		assertContains(t, importedFingerprints, fingerprint)
	})

}

func TestDeduplicate(t *testing.T) {

	slice := []fingerprint.Fingerprint{
		exampleFingerprintA,
		exampleFingerprintA,
		exampleFingerprintB,
		exampleFingerprintC,
	}

	got := deduplicate(slice)
	want := []fingerprint.Fingerprint{
		exampleFingerprintA,
		exampleFingerprintB,
		exampleFingerprintC,
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

func assertContains(t *testing.T, slice []fingerprint.Fingerprint, element fingerprint.Fingerprint) {
	t.Helper()
	if !contains(slice, element) {
		t.Fatalf("Expected '%v' to contain '%v'", slice, element)
	}
}

func contains(s []fingerprint.Fingerprint, e fingerprint.Fingerprint) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

var exampleFingerprintA = fingerprint.MustParse("AAAA AAAA AAAA AAAA AAAA  AAAA AAAA AAAA AAAA AAAA")
var exampleFingerprintB = fingerprint.MustParse("BBBB BBBB BBBB BBBB BBBB  BBBB BBBB BBBB BBBB BBBB")
var exampleFingerprintC = fingerprint.MustParse("CCCC CCCC CCCC CCCC CCCC  CCCC CCCC CCCC CCCC CCCC")
