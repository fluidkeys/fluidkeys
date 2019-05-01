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

var scheduler schedulerInterface

func init() {
	scheduler = &cron{}
}

// Enable schedules Fluidkeys sync task to run regularly
func Enable() (bool, error) {
	return scheduler.Enable()
}

// Disable stops Fluidkeys sync task from running regularly
func Disable() (bool, error) {
	return scheduler.Disable()
}

// Name returns a friendly name for the scheduler
func Name() string {
	return scheduler.Name()
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
