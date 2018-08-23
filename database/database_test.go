package database

import (
	"io/ioutil"
	"testing"
)

func TestRecordFingerprintImportedIntoGnuPG(t *testing.T) {

	t.Run("record works to an empty database", func(t *testing.T) {
		fingerprint := string("FOO")
		database := New(makeTempDirectory(t))
		err := database.RecordFingerprintImportedIntoGnuPG(fingerprint)
		assertErrorIsNil(t, err)

		importedFingerprints, err := database.GetFingerprintsImportedIntoGnuPG()
		assertContains(t, importedFingerprints, fingerprint)
	})

	t.Run("record appends a new key to a database with key ids already stored", func(t *testing.T) {
		existingFingerprint := string(1234)
		newFingerprint := string(5678)
		database := New(makeTempDirectory(t))

		err := database.RecordFingerprintImportedIntoGnuPG(existingFingerprint)
		assertErrorIsNil(t, err)
		err = database.RecordFingerprintImportedIntoGnuPG(newFingerprint)
		assertErrorIsNil(t, err)

		importedFingerprints, err := database.GetFingerprintsImportedIntoGnuPG()
		assertContains(t, importedFingerprints, existingFingerprint)
		assertContains(t, importedFingerprints, newFingerprint)
	})

	t.Run("doesn't duplicate key ids if trying to record a key that already is stored", func(t *testing.T) {
		fingerprint := string(1234)
		database := New(makeTempDirectory(t))

		err := database.RecordFingerprintImportedIntoGnuPG(fingerprint)
		assertErrorIsNil(t, err)
		err = database.RecordFingerprintImportedIntoGnuPG(fingerprint)
		assertErrorIsNil(t, err)

		importedFingerprints, err := database.GetFingerprintsImportedIntoGnuPG()
		if len(importedFingerprints) != 1 {
			t.Errorf("Expected 1 entry in slice, '%v'", importedFingerprints)
		}
	})
}

func TestGetFingerprintsImportedIntoGnuPG(t *testing.T) {

	t.Run("can read back fingerprint written to database", func(t *testing.T) {
		database := New(makeTempDirectory(t))
		fingerprint := string(1234)
		err := database.RecordFingerprintImportedIntoGnuPG(fingerprint)
		assertErrorIsNil(t, err)

		importedFingerprints, err := database.GetFingerprintsImportedIntoGnuPG()
		assertErrorIsNil(t, err)
		assertContains(t, importedFingerprints, fingerprint)
	})

}

func TestDeduplicate(t *testing.T) {

	slice := []string{"FOO", "FOO", "BAR", "BAZ"}

	got := deduplicate(slice)
	want := []string{"FOO", "BAR", "BAZ"}

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

func assertContains(t *testing.T, slice []string, element string) {
	t.Helper()
	if !contains(slice, element) {
		t.Fatalf("Expected '%v' to contain '%v'", slice, element)
	}
}

func assertErrorIsNil(t *testing.T, got error) {
	t.Helper()
	if got != nil {
		t.Fatalf("got an error but didnt want one '%s'", got)
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
