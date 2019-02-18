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

package gpgwrapper

import (
	"fmt"
	"os/exec"
)

// BackupHomeDir makes a .tar backup file of the user's GnuPG directory
// to the given filepath
func (g *GnuPG) BackupHomeDir(filepath string) (string, error) {
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
