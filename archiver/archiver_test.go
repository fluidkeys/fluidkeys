package archiver

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
)

func TestMakeFilePath(t *testing.T) {
	now := time.Date(2018, 6, 15, 15, 32, 1, 0, time.UTC)
	directory, err := ioutil.TempDir("", "fluidkey.backup_test_directory.")
	if err != nil {
		t.Fatalf("error creating temporary directory")
	}
	filename := "foo"
	extension := "txt"

	expect := directory + "/backups/2018-06-15/foo-2018-06-15T15-32-01.txt"
	got, err := MakeFilePath(filename, extension, directory, now)

	assert.ErrorIsNil(t, err)
	assert.Equal(t, expect, got)
}
