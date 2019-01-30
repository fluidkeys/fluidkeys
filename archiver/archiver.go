// Copyright 2018 Paul Furley and Ian Drysdale
//
// This file is part of Fluidkeys Client which makes it simple to use OpenPGP.
//
// Fluidkeys Client is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Fluidkeys Client is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Fluidkeys Client.  If not, see <https://www.gnu.org/licenses/>.

package archiver

import (
	"os"
	"path/filepath"
	"time"
)

// MakeFilePath takes a filename, extension, directory and time and constructs
// a filepath string formated like:
//   directory/2016-08-23/filename-2016-08-23T18-05-00.ext
// If the directory doesn't exist, it is created.
func MakeFilePath(
	filename string, extension string, directory string, now time.Time) (string, error) {

	directory, err := dateStampedDirectory(directory, now)
	if err != nil {
		return "", err
	}

	return filepath.Join(directory, appendTimeStampToFilename(filename, extension, now)), nil
}

func appendTimeStampToFilename(filename string, extension string, now time.Time) string {
	timestamp := now.Format("2006-01-02T15-04-05")
	return filename + "-" + timestamp + "." + extension
}

func dateStampedDirectory(fluidkeysDir string, now time.Time) (string, error) {
	dateSubdirectory := now.Format("2006-01-02")
	backupDirectory := filepath.Join(fluidkeysDir, "backups", dateSubdirectory)
	err := os.MkdirAll(backupDirectory, 0700)
	return backupDirectory, err
}
