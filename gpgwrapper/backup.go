package gpgwrapper

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func (g *GnuPG) BackupHomeDir(filepath string, now time.Time) (string, error) {
	cmd := "tar"
	gpgHomeDir, err := g.HomeDir()
	if err != nil {
		return "", fmt.Errorf("error finding GPG home directory: %v", err)
	}
	args := []string{"-czf", filepath, "-C", gpgHomeDir, "."}
	if err := exec.Command(cmd, args...).Run(); err != nil {
		return "", fmt.Errorf("error executing tar -czf (...): %v", err)
	}
	return filepath, nil
}
