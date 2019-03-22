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

package table

import (
	"github.com/fluidkeys/fluidkeys/colour"
)

// A PersonRow is used to format a row in the table
type PersonRow struct {
	Email              string
	TimeSinceLastFetch string
	IsAdmin            bool
}

// FormatPeopleTable takes a slice of people rows and returns a string containing a formatted table.
func FormatPeopleTable(peopleRows []PersonRow) (output string) {
	personRows := makePeopleTableRows(peopleRows)
	rowStrings := formatTableStringsFromRows(personRows)
	for _, rowString := range rowStrings {
		output += rowString + "\n"
	}
	return output + "\n"
}

func makePeopleTableRows(peopleRows []PersonRow) (rows []row) {
	placeholderDividerRow := row{divider, divider, divider}

	rows = append(rows, peopleHeader)
	rows = append(rows, placeholderDividerRow)
	for _, peopleRow := range peopleRows {
		rows = append(rows, []string{
			peopleRow.Email,
			peopleRow.TimeSinceLastFetch,
			printAdminIfTrue(peopleRow.IsAdmin),
		})
		rows = append(rows, placeholderDividerRow)
	}
	return rows
}

var peopleHeader = row{
	colour.TableHeader("Team Member"),
	colour.TableHeader("Last Fetched"),
	colour.TableHeader(""),
}

func printAdminIfTrue(status bool) string {
	if status {
		return "admin"
	}
	return ""
}
