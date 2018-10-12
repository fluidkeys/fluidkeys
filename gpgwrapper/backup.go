package gpgwrapper

import (
	"os/exec"
	"path/filepath"
	"time"

	"github.com/fluidkeys/fluidkeys/archiver"
)

func (g *GnuPG) BackupHomeDir(fluidkeysDir string, now time.Time) (string, error) {
	cmd := "tar"
	directory := archiver.DateStampedDirectory(fluidkeysDir, now)
	filename := filepath.Join(directory, "gpghome.tgz")
	args := []string{"-czf", filename, "-C", g.HomeDir(), "."}
	if err := exec.Command(cmd, args...).Run(); err != nil {
		return "", err
	}
	return filename, nil
}
