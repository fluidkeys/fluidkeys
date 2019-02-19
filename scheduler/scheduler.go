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

package scheduler

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"
	"syscall"
)

// Enable adds cron lines to the user's crontab and returns whether the
// crontab was updated.
func Enable(crontab runCrontabInterface) (crontabWasAdded bool, err error) {
	if crontab == nil {
		crontab = &systemCrontab{}
	}

	currentCrontab, err := getCurrentCrontab(crontab)
	if err != nil {
		return false, fmt.Errorf("error getting crontab: %v", err)
	}

	if !hasFluidkeysCronLines(currentCrontab) {
		newCrontab := addCrontabLinesWithoutRepeating(currentCrontab)
		err = writeCrontab(newCrontab, crontab)
		return true, err
	}

	return false, nil
}

// Disable parses the crontab (output of `crontab -l`) and removes Fluidkeys'
// cron lines if present.
// If the remaining crontab is empty, the crontab is removed with `crontab -r`
func Disable(crontab runCrontabInterface) (cronLinesWereRemoved bool, err error) {
	if crontab == nil {
		crontab = &systemCrontab{}
	}

	currentCrontab, err := getCurrentCrontab(crontab)
	if err != nil {
		return false, fmt.Errorf("error getting crontab: %v", err)
	}

	if hasFluidkeysCronLines(currentCrontab) {
		newCrontab := removeCrontabLines(currentCrontab)
		err = writeCrontab(newCrontab, crontab)
		return true, err
	}
	return false, nil
}

func hasFluidkeysCronLines(crontab string) bool {
	return strings.Contains(crontab, cronLines)
}

func getCurrentCrontab(crontab runCrontabInterface) (string, error) {
	output, err := crontab.runCrontab("-l")
	if err != nil {
		if isExitStatusOne(err) && strings.Contains(output, "no crontab for") {
			return "", nil
		}
	}
	return output, err
}

func writeCrontab(newCrontab string, crontab runCrontabInterface) error {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		return err
	}

	if _, err := io.WriteString(f, newCrontab); err != nil {
		return fmt.Errorf("error writing crontab: %v", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("error closing crontab: %v", err)
	}

	_, err = crontab.runCrontab(f.Name())
	return err
}

func isExitStatusOne(err error) bool {
	if exiterr, ok := err.(*exec.ExitError); ok {
		if _, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			return true
		}
	}
	return false
}

type systemCrontab struct{}

func (*systemCrontab) runCrontab(arguments ...string) (string, error) {
	log.Printf("Running `%s %s`", crontab, strings.Join(arguments, " "))
	cmd := exec.Command(crontab, arguments...)

	out, err := cmd.CombinedOutput()

	outString := string(out)

	if err != nil {
		return outString, err
	}
	return outString, nil
}

func addCrontabLinesWithoutRepeating(crontab string) string {
	return removeCrontabLines(crontab) + cronLines
}

func removeCrontabLines(crontab string) string {
	return strings.Replace(crontab, cronLines, "", -1)
}

const crontab string = "crontab"
const cronLines string = `
# Fluidkeys added the following line. To disable, edit your Fluidkeys configuration file.
@hourly /usr/local/bin/fk key maintain automatic --cron-output
`
