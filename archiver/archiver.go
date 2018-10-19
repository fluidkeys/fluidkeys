package archiver

import (
	"os"
	"path/filepath"
	"time"
)

// MakeFilePath takes a filename, extension, directory and time and constructs
// a filepath string formated like:
//   directory/2016-08-23/filename-180500.ext
func MakeFilePath(filename string, extension string, directory string, now time.Time) string {
	return filepath.Join(
		dateStampedDirectory(directory, now),
		appendTimeStampToFilename(filename, extension, now),
	)
}

func appendTimeStampToFilename(filename string, extension string, now time.Time) string {
	timestamp := now.Format("150405")
	return filename + "-" + timestamp + "." + extension
}

func dateStampedDirectory(fluidkeysDir string, now time.Time) string {
	dateSubdirectory := now.Format("2006-01-02")
	backupDirectory := filepath.Join(fluidkeysDir, "backups", dateSubdirectory)
	os.MkdirAll(backupDirectory, 0700)
	return backupDirectory
}
