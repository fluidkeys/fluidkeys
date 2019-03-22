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
	"fmt"
	"strings"

	"github.com/fluidkeys/fluidkeys/colour"
)

// formatTableStringsFromRows takes a slice of rows and coverts it into a slice of
// strings, padding out the space between the values appropriately.
// e.g. ["Jane", "4", "Sheffield"], -> "Jane     4   Sheffield",
//      ["Gillian", "23", "Hull"]      "Gillian  23  Hull     "
func formatTableStringsFromRows(rows []row) []string {
	var rowStrings []string
	maxColumnWidths := getColumnWidths(rows)

	for _, row := range rows {
		var rowString string
		for columnIndex, value := range row {
			if value == divider {
				rowString += makeDividerString(maxColumnWidths[columnIndex])
			} else {
				rowString += makeCellString(value, maxColumnWidths[columnIndex])
			}
		}
		rowString = strings.TrimSuffix(rowString, gutter)
		rowStrings = append(rowStrings, rowString)
	}

	return rowStrings
}

// makeDividerString substitutes in our placeholder '---' with horizontal
// strings equal to the specified length. For example: 8 -> '────────'
func makeDividerString(length int) string {
	return fmt.Sprintf("%s%s", strings.Repeat("─", length), gutter)
}

func makeCellString(value string, cellLength int) string {
	return fmt.Sprintf(
		"%s%s%s",
		value,
		// This is more complicated since we have colours on strings
		strings.Repeat(" ", cellLength-len(colour.StripAllColourCodes(value))),
		gutter,
	)
}

type row = []string

const gutter = "  "
const divider = "---"
