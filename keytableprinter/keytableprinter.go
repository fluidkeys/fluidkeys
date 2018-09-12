package keytableprinter

import (
	"fmt"
	"strings"

	"github.com/fluidkeys/fluidkeys/pgpkey"
)

const gutter = "  "

var headers = [3]string{
	"Email address",
	"Created",
	"Next rotation",
}

func Print(keys []pgpkey.PgpKey) {
	fmt.Printf("%s\n", makeTable(keys))
}

func makeTable(keys []pgpkey.PgpKey) string {
	var table string
	table += fmt.Sprintf("%s\n", makeHeader(columnWidths(keys)))
	table += fmt.Sprintf("%s\n", makeHorizontalUnderlines(columnWidths(keys)))

	for _, key := range keys {
		firstEmail := key.Emails(true)[0]
		table += fmt.Sprintf("%-*s%s", columnWidths(keys)[0], firstEmail, gutter)
		table += fmt.Sprintf("%-*s", columnWidths(keys)[1], key.PrimaryKey.CreationTime.Format("2 Jan 2006"))
		table += fmt.Sprintf("\n")
		for _, email := range key.Emails(true)[1:] {
			table += fmt.Sprintf("%v\n", email)
		}

		table += fmt.Sprintf("%s\n", makeHorizontalUnderlines(columnWidths(keys)))
	}
	return table
}

// makeHeader returns a string representing the header with the appropriate
// spacing to match the column widths provided, e.g.
// 'Email address          Created     Next rotation'
func makeHeader(columnWidths [3]int) string {
	var header string
	for column, value := range headers {
		header += fmt.Sprintf("%-*s%s", columnWidths[column], value, gutter)
	}
	return fmt.Sprintf("%s", strings.TrimSuffix(header, gutter))
}

// columnWidths returns the widths of each column in characters
func columnWidths(keys []pgpkey.PgpKey) [3]int {
	var columnWidths [3]int

	// Set column widths to header widths
	for index, headerColumn := range headers {
		columnWidths[index] = len(headerColumn)
	}

	// Check if column widths need to be extended for cell content
	for _, key := range keys {
		for _, email := range key.Identities {
			columnWidths[0] = max(columnWidths[0], len(email.Name))
		}
		columnWidths[1] = max(columnWidths[1], len(key.PrimaryKey.CreationTime.Format("2 Jan 2006")))
		// TODO: check on rotation date cell when implemented
	}

	return columnWidths
}

// makeHorizontalUnderlines takes an array of integers and for each integer it
// prints a horizontal line equivalent to it's length, followed by a gutter.
// eg [3, 2, 5] => '───  ──  ─────'
func makeHorizontalUnderlines(columnWidths [3]int) string {
	var underlines string
	for _, columnWidth := range columnWidths {
		underlines += fmt.Sprintf("%s%s", strings.Repeat("─", columnWidth), gutter)
	}
	return strings.TrimSuffix(underlines, gutter)
}

// max returns the larger of x or y.
func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}
