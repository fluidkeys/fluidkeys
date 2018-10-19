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

	expect := directory + "/backups/2018-06-15/foo-153201.txt"
	got := MakeFilePath(filename, extension, directory, now)

	assert.Equal(t, expect, got)
}
