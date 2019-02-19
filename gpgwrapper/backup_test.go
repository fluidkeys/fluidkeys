package gpgwrapper

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupHomeDir(t *testing.T) {
	tmpDirectory, err := ioutil.TempDir("", "fluidkeys")
	tmpFilePath := filepath.Join(tmpDirectory, "example.tgz")
	if err != nil {
		t.Fatalf("error making temp fluidkeys directory: %v\n", err)
	}
	gpg := makeGpgWithTempHome(t)

	filename, _ := gpg.BackupHomeDir(tmpFilePath)

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Fatalf("Expected %v to exist, but it doesn't", filename)
	}
}
