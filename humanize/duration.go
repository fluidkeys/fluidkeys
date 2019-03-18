// Copyright 2019 Paul Furley and Ian Drysdale
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

package humanize

import (
	"math"
	"time"
)

// RoughDuration returns a rough duration as a number of minutes, hours or days, for example
// "2 minutes", "11 days"
func RoughDuration(d time.Duration) string {
	switch {
	case 0 <= d && d < oneMinute:
		return "just now"

	case oneMinute <= d && d < oneHour:
		return Pluralize(int(math.Floor(d.Minutes())), "minute", "minutes")

	case oneHour <= d && d < oneDay:
		return Pluralize(int(math.Floor(0.5+d.Hours())), "hour", "hours")

	case oneDay <= d:
		return Pluralize(int(math.Floor(d.Hours()/24)), "day", "days")

	default:
		return "don't know"

	}
}

const (
	oneMinute = time.Duration(1) * time.Minute
	oneHour   = time.Duration(1) * time.Hour
	oneDay    = time.Duration(24) * time.Hour
)
