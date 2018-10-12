package gpgwrapper

import (
	"os/exec"
	"time"
)

func (g *GnuPG) BackupHomeDir(filepath string, now time.Time) (string, error) {
	cmd := "tar"
	gpgHomeDir, err := g.HomeDir()
	if err != nil {
		return "Error findings GPG home directory: %v", err
	}
	args := []string{"-czf", filepath, "-C", gpgHomeDir, "."}
	if err := exec.Command(cmd, args...).Run(); err != nil {
		return "Error executing tar -czf (...): %v", err
	}
	return filepath, nil
}
