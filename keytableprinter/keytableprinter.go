package keytableprinter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/status"
)

type column = []string
type row = []string

const gutter = "  "
const divider = "---"

var header = row{
	colour.TableHeader("Email address"),
	colour.TableHeader("Created"),
	colour.TableHeader("Status"),
}

var placeholderDividerRow = row{divider, divider, divider}

func Print(keys []pgpkey.PgpKey) {
	rows := makeTableRows(keys)
	rowStrings := makeStringsFromRows(rows)
	for _, rowString := range rowStrings {
		fmt.Println(rowString)
	}

	printTopLevelHint(keys)
}

func makeTableRows(keys []pgpkey.PgpKey) []row {
	var rows []row
	rows = append(rows, header)
	rows = append(rows, placeholderDividerRow)
	rows = append(rows, makeRowsForKeys(keys)...)
	return rows
}

// makeRowsForKeys takes a slice of PgpKeys and returns a slice of rows
// representing the emails, creation time and warning lines associated for
// each key.
// e.g ->   [['jane@example.com', '12 Jan 1998', 'Due for rotation',
//           ['jane@work.com', '', 'Another warning']]
// It adds a dividing line between each key
func makeRowsForKeys(keys []pgpkey.PgpKey) []row {
	var allRows []row
	for _, key := range keys {
		columns := []column{
			key.Emails(true),
			[]string{key.PrimaryKey.CreationTime.Format("2 Jan 2006")},
			keyStatus(key, status.GetKeyWarnings(key)),
		}
		keyRows := makeRowsFromColumns(columns)
		allRows = append(allRows, keyRows...)
		allRows = append(allRows, placeholderDividerRow)
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

// makeStringsFromRows takes a slice of rows and coverts it into a slice of
// strings, padding out the space between the values appropriately.
// e.g. ["Jane", "4", "Sheffield"], -> "Jane     4   Sheffield",
//      ["Gillian", "23", "Hull"]      "Gillian  23  Hull     "
func makeStringsFromRows(rows []row) []string {
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
	} else {
		return x
	}
}

// printTopLevelHint prints single hint to suggest the user should run fk key
// rotate if any of their keys are overdue for rotation or due for rotation.
func printTopLevelHint(keys []pgpkey.PgpKey) {
	var warnings []status.KeyWarning
	for _, key := range keys {
		warnings = append(warnings, status.GetKeyWarnings(key)...)
	}
	if warningsSliceContainsType(warnings, status.PrimaryKeyOverdueForRotation) ||
		warningsSliceContainsType(warnings, status.SubkeyOverdueForRotation) {
		fmt.Println(colour.Danger(`[!] Your key(s) are overdue for rotation.
They will expire unless you rotate them by running:
    fk key rotate`))
		return
	}
	if warningsSliceContainsType(warnings, status.PrimaryKeyDueForRotation) ||
		warningsSliceContainsType(warnings, status.SubkeyDueForRotation) {
		fmt.Println(colour.Warning(`[!] Rotate your key(s) by running: fk key rotate`))
		return
	}
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
