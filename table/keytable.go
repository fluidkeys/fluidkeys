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

package table

import (
	"sort"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/status"
)

// A KeyWithWarnings defines a key with a slice of warnings used to format
// a row in the table
type KeyWithWarnings struct {
	Key      *pgpkey.PgpKey
	Warnings []status.KeyWarning
}

// FormatKeyTable takes a slice of keys with warnings and returns a string containing
// a formatted table of the keys, warnings and an instruction to the user
// on what they might do to resolve the warnings.
func FormatKeyTable(keysWithWarnings []KeyWithWarnings) (output string) {
	output = makeTable(keysWithWarnings)
	output = output + makePrimaryInstruction(keysWithWarnings)
	return output
}

func makeTable(keysWithWarnings []KeyWithWarnings) (output string) {
	rows := makeTableRows(keysWithWarnings)
	rowStrings := formatTableStringsFromRows(rows)
	for _, rowString := range rowStrings {
		output += rowString + "\n"
	}
	return output + "\n"
}

func makeTableRows(keysWithWarnings []KeyWithWarnings) []row {
	var rows []row
	rows = append(rows, header)
	rows = append(rows, keyTablePlaceholderDividerRow)
	rows = append(rows, makeRowsForKeys(keysWithWarnings)...)
	return rows
}

// makeRowsForKeys takes a slice of PgpKeys and returns a slice of rows
// representing the emails, creation time and warning lines associated for
// each key.
// e.g ->   [['jane@example.com', '12 Jan 1998', 'Due for rotation',
//           ['jane@work.com', '', 'Another warning']]
// It adds a dividing line between each key
func makeRowsForKeys(keysWithWarnings []KeyWithWarnings) []row {
	var allRows []row
	for _, keyWithWarnings := range keysWithWarnings {
		columns := []column{
			keyWithWarnings.Key.Emails(true),
			[]string{keyWithWarnings.Key.PrimaryKey.CreationTime.Format("2 Jan 2006")},
			keyStatus(*keyWithWarnings.Key, keyWithWarnings.Warnings),
		}
		keyRows := makeRowsFromColumns(columns)
		allRows = append(allRows, keyRows...)
		allRows = append(allRows, keyTablePlaceholderDividerRow)
	}
	return allRows
}

// makeRows takes a slice of columns, and returns a slice of rows.
// It pads out any of the shorter columns with empty cells.
// e.g.  Columns  : ["Jim", "Jane", "Fi"], ["1", "2"]
//       => Rows  : [["Jim", "1"], ["Jane", "2"], ["Fi", ""]]
func makeRowsFromColumns(columns []column) []row {
	var rows []row

	columnLengths := make([]int, len(columns))
	for i, column := range columns {
		columnLengths[i] = len(column)
	}

	totalRows := maxInSlice(columnLengths)
	var lengthenedColumns []column

	for _, column := range columns {
		lengthenedColumn := lengthenWithEmptyCells(column, totalRows)
		lengthenedColumns = append(lengthenedColumns, lengthenedColumn)
	}

	for rowCounter := 0; rowCounter < totalRows; rowCounter++ {
		var row row
		for _, column := range lengthenedColumns {
			row = append(row, column[rowCounter])
		}
		rows = append(rows, row)
	}

	return rows
}

// lengthenWithEmptyCells takes a column, fills it with blank cells such
// that it becomes the required length and returns this new column.
func lengthenWithEmptyCells(column column, requiredLength int) column {
	missingCells := requiredLength - len(column)
	for i := 0; i < missingCells; i++ {
		column = append(column, "")
	}
	return column
}

// getColumnWidths takes a slice of rows and then finds the length of the
// longest value in each column.
func getColumnWidths(rows []row) []int {
	if len(rows) == 0 {
		return []int{}
	}
	maxColumnWidths := make(map[int]int) // Column index -> Maximum width

	for _, row := range rows {
		for columnIndex, value := range row {
			maxColumnWidths[columnIndex] = max(
				maxColumnWidths[columnIndex],
				len(colour.StripAllColourCodes(value)),
			)
		}
	}

	var result []int
	for columnIndex := 0; columnIndex < len(rows[0]); columnIndex++ {
		result = append(result, maxColumnWidths[columnIndex])
	}
	return result
}

// maxInSlice returns the larget int in the slice
func maxInSlice(values []int) int {
	sliceNumbers := sort.IntSlice(values)
	sort.Sort(sliceNumbers)
	largest := sliceNumbers[len(sliceNumbers)-1]
	return largest
}

// max returns the larger of x or y.
func max(x int, y int) int {
	if x < y {
		return y
	}
	return x
}

// makePrimaryInstruction prints single instruction to the user to run
// 'fk key maintain' if they have any issues with their keys. The severity of
// the message depends on if they have any urgent issues.
func makePrimaryInstruction(keysWithWarnings []KeyWithWarnings) string {
	var warnings []status.KeyWarning
	for _, keyWithWarnings := range keysWithWarnings {
		warnings = append(warnings, keyWithWarnings.Warnings...)
	}
	var output string
	if len(warnings) > 0 {
		if warningsSliceContainsType(warnings, status.PrimaryKeyOverdueForRotation) ||
			warningsSliceContainsType(warnings, status.SubkeyOverdueForRotation) {
			output = "Prevent your key(s) from becoming unusable by running:\n"
		}
		if warningsSliceContainsType(warnings, status.PrimaryKeyExpired) ||
			warningsSliceContainsType(warnings, status.NoValidEncryptionSubkey) {
			output = "Make your key(s) usable again by running:\n"
		} else { // These aren't urgent issues
			output = "Fix these issues by running:\n"
		}
		output += "    " + colour.Cmd("fk key maintain") + "\n"
		output += "    " + colour.Cmd("fk key upload") + "\n\n"
	}
	return output
}

// contains returns true if the given needle (Warning) is present in the
// given haystack pointing at it, false if not.
func warningsSliceContainsType(haystack []status.KeyWarning, needle status.WarningType) bool {
	for _, value := range haystack {
		if value.Type == needle {
			return true
		}
	}
	return false
}

// keyStatus takes a key and slice of warnings and returns a slice of coloured
// strings for printing in the table. If no warnings, the status is reported as
// Good
func keyStatus(key pgpkey.PgpKey, keyWarnings []status.KeyWarning) []string {
	keyWarningLines := []string{}
	if len(keyWarnings) > 0 {
		for _, keyWarning := range keyWarnings {
			keyWarningLines = append(
				keyWarningLines,
				keyWarning.String(),
			)
		}
	} else {
		keyWarningLines = append(keyWarningLines, colour.Success("Good ✔"))
	}
	return keyWarningLines
}

var header = row{
	colour.TableHeader("Email address"),
	colour.TableHeader("Created"),
	colour.TableHeader("Status"),
}

var keyTablePlaceholderDividerRow = row{divider, divider, divider}

type column = []string
