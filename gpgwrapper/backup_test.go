package gpgwrapper

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupHomeDir(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	tmpDirectory, err := ioutil.TempDir("", "fluidkeys")
	tmpFilePath := filepath.Join(tmpDirectory, "example.tgz")
	if err != nil {
		t.Fatalf("error making temp fluidkeys directory: %v\n", err)
	}
	gpg := GnuPG{homeDir: makeTempGnupgHome(t)}

	filename, _ := gpg.BackupHomeDir(tmpFilePath, now)

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Fatalf("Expected %v to exist, but it doesn't", filename)
	}
}
