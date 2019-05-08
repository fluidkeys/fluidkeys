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
	"log"
	"os/exec"

	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/ui"
)

var scheduler schedulerInterface

func init() {
	_, err := exec.LookPath(launchctl)
	if err != nil {
		scheduler = &cron{}
	} else {
		scheduler = &launchd{}
	}
}

// Enable schedules Fluidkeys sync task to run regularly
func Enable() (bool, error) {
	schedulerWasEnabled, err := scheduler.Enable()

	if err == nil && schedulerWasEnabled {
		if _, isLaunchd := scheduler.(*launchd); isLaunchd {
			tryDisableCrontab()
		}
	}

	return schedulerWasEnabled, err
}

// Disable stops Fluidkeys sync task from running regularly
func Disable() (bool, error) {
	return scheduler.Disable()
}

// Name returns a friendly name for the scheduler
func Name() string {
	return scheduler.Name()
}

// tryDisableCrontab is used to try and remove the fluidkeys lines from crontab, immediately
// after successfully enabling launchd.
func tryDisableCrontab() {
	c := cron{}

	enabled, err := c.IsEnabled()
	if err != nil {
		log.Printf("failed to check crontab (migrating to launchd): %v", err)
		return
	} else if !enabled {
		return
	}

	out.Print("Fluidkeys no longer uses cron to run in the background.\n")
	out.Print("Removing leftover lines from crontab.\n\n")

	err = ui.RunWithCheckboxes("edit crontab to remove Fluidkeys lines", func() error {
		wasDisabled, err := c.Disable()

		if err != nil {
			log.Printf("failed to disable crontab (migrating to launchd): %v", err)
		} else if wasDisabled {
			log.Printf("disabled Fluidkeys in crontab")
		}
		return err
	})
	out.Print("\n")

	if err != nil {
		out.Print("To remove Fluidkeys from crontab manually, see:\n")
		out.Print("https://www.fluidkeys.com/docs/remove-crontab-lines-macos-mojave/\n")
	}
}

// schedulerInterface provides the uniform interface for scheduling a task on the
// operating system
type schedulerInterface interface {
	// Enable turns on scheduling with the given interface
	Enable() (bool, error)
	// Disable turns off scheduling with the given interface
	Disable() (bool, error)
	// Name returns a friendly name for the scheduler
	Name() string
}
