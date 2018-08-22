package database

import (
	"io/ioutil"
	"testing"
)

func TestRecordKeyIdImportedIntoGnuPG(t *testing.T) {

	t.Run("record works to an empty database", func(t *testing.T) {
		keyId := uint64(1234)
		database := New(makeTempDirectory(t))
		err := database.RecordKeyIdImportedIntoGnuPG(keyId)
		assertErrorIsNil(t, err)

		importedKeyIds, err := database.GetKeyIdsImportedIntoGnuPG()
		assertContains(t, importedKeyIds, keyId)
	})

	t.Run("record appends a new key to a database with key ids already stored", func(t *testing.T) {
		existingKeyId := uint64(1234)
		newKeyId := uint64(5678)
		database := New(makeTempDirectory(t))

		err := database.RecordKeyIdImportedIntoGnuPG(existingKeyId)
		assertErrorIsNil(t, err)
		err = database.RecordKeyIdImportedIntoGnuPG(newKeyId)
		assertErrorIsNil(t, err)

		importedKeyIds, err := database.GetKeyIdsImportedIntoGnuPG()
		assertContains(t, importedKeyIds, existingKeyId)
		assertContains(t, importedKeyIds, newKeyId)
	})

	t.Run("doesn't duplicate key ids if trying to record a key that already is stored", func(t *testing.T) {
		keyId := uint64(1234)
		database := New(makeTempDirectory(t))

		err := database.RecordKeyIdImportedIntoGnuPG(keyId)
		assertErrorIsNil(t, err)
		err = database.RecordKeyIdImportedIntoGnuPG(keyId)
		assertErrorIsNil(t, err)

		importedKeyIds, err := database.GetKeyIdsImportedIntoGnuPG()
		if len(importedKeyIds) != 1 {
			t.Errorf("Expected 1 entry in slice, '%v'", importedKeyIds)
		}
	})
}

func TestGetKeyIdsImportedIntoGnuPG(t *testing.T) {

	t.Run("can read back keyId written to database", func(t *testing.T) {
		database := New(makeTempDirectory(t))
		keyId := uint64(1234)
		err := database.RecordKeyIdImportedIntoGnuPG(keyId)
		assertErrorIsNil(t, err)

		importedKeyIds, err := database.GetKeyIdsImportedIntoGnuPG()
		assertErrorIsNil(t, err)
		assertContains(t, importedKeyIds, keyId)
	})

}

func TestDeduplicate(t *testing.T) {

	slice := []uint64{1, 1, 2, 2, 2, 3, 4}

	got := deduplicate(slice)
	want := []uint64{1, 2, 3, 4}

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

func assertContains(t *testing.T, slice []uint64, element uint64) {
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

func contains(s []uint64, e uint64) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
