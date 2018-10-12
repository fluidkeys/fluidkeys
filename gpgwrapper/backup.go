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
	gpgHomeDir, err := g.HomeDir()
	if err != nil {
		return "Error findings GPG home directory: %v", err
	}
	args := []string{"-czf", filename, "-C", gpgHomeDir, "."}
	if err := exec.Command(cmd, args...).Run(); err != nil {
		return "Error executing tar -czf (...): %v", err
	}
	return filename, nil
}
