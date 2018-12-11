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

package humanize

import (
	"fmt"
	"strconv"
)

// Plural returns the quantity then either the `singular` (fox) or `plural`
// (foxes) depending on that given `quantity`
// e.g. `Plural(2, "fox", "foxes")` returns "2 foxes"
func Pluralize(quantity int, singular, plural string) string {
	str := fmt.Sprintf("%s ", strconv.Itoa(quantity))
	if quantity == 1 {
		str += singular
	} else {
		str += plural
	}
	return str
}
