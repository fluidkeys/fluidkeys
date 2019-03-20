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
)

// Enable adds cron lines to the user's crontab and returns whether the
// crontab was updated.
func Enable(crontab runCrontabInterface) (crontabWasAdded bool, err error) {
	if crontab == nil {
		crontab = &systemCrontab{}
	}

	currentCrontab, err := crontab.get()
	if err != nil {
		return false, fmt.Errorf("error getting crontab: %v", err)
	}

	if !hasFluidkeysCronLines(currentCrontab) {
		newCrontab := addCrontabLinesWithoutRepeating(currentCrontab)
		err = crontab.set(newCrontab)
		if err != nil {
			return false, err
		}
		return true, nil
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

	currentCrontab, err := crontab.get()
	if err != nil {
		return false, fmt.Errorf("error getting crontab: %v", err)
	}

	if hasFluidkeysCronLines(currentCrontab) {
		newCrontab := removeCrontabLines(currentCrontab)
		err = crontab.set(newCrontab)

		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func hasFluidkeysCronLines(crontab string) bool {
	return strings.Contains(crontab, strings.TrimSuffix(CronLines, "\n"))
}

type systemCrontab struct{}

func (s *systemCrontab) get() (string, error) {
	output, err := s.runCrontab("-l")

	if s.isNoCrontabError(output, err) {
		return "", nil
	}

	return output, err
}

func (s *systemCrontab) set(newCrontab string) error {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		return fmt.Errorf("error opening temp file: %v", err)
	}

	if _, err := io.WriteString(f, newCrontab); err != nil {
		return fmt.Errorf("error writing to temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("error closing temp file: %v", err)
	}

	if _, err := s.runCrontab(f.Name()); err != nil {
		return fmt.Errorf("error updating crontab: %v", err)
	}
	return nil
}

// isNoCrontabError returns true if and only if the error looks like a failure from `crontab -l`
// of the form "no crontab for foo"
func (s *systemCrontab) isNoCrontabError(cronOutput string, err error) bool {
	if err == nil {
		return false
	}

	return isExitError(err) && strings.Contains(cronOutput, "no crontab for")
}

func isExitError(err error) bool {
	if _, ok := err.(*exec.ExitError); ok {
		return true
	}
	return false
}

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
	removed := removeCrontabLines(crontab)

	if !strings.HasSuffix(removed, "\n") {
		// the crontab should always have a trailing newline
		removed += "\n"
	}

	if isEmpty(removed) {
		return CronLines
	}

	return removed + "\n" + CronLines
}

func removeCrontabLines(crontab string) string {
	linesWithoutFinalNewline := strings.TrimSuffix(CronLines, "\n")

	result := strings.Replace(crontab, linesWithoutFinalNewline, "", -1)
	if isEmpty(result) {
		return ""
	}
	return strings.Trim(result, "\n") + "\n"
}

func isEmpty(crontab string) bool {
	return strings.Trim(crontab, "\n") == ""
}

const crontab string = "crontab"

// CronLines is the string Fluidkeys adds to a user's crontab to run itself
const CronLines string = "# Fluidkeys added the following line. To disable, edit your " +
	"Fluidkeys configuration file.\n" +
	"@hourly /usr/local/bin/fk key maintain automatic --cron-output\n"
