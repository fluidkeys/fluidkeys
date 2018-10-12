package archiver

import (
	"os"
	"path/filepath"
	"time"
)

func DateStampedDirectory(fluidkeysDir string, now time.Time) string {
	dateSubdirectory := now.Format("2006-01-02")
	backupDirectory := filepath.Join(fluidkeysDir, "backups", dateSubdirectory)
	os.MkdirAll(backupDirectory, 0700)
	return backupDirectory
}
