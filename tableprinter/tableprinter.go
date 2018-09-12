package tableprinter

import (
	"fmt"
	"strings"

	"github.com/fluidkeys/fluidkeys/colour"
)

const gutterWidth = 2

type Row struct {
	columns []string
}

type TablePrinter struct {
	headers Row
	rows    []Row
}

func (tp *TablePrinter) PushRow(columnCells Row) {
	tp.rows = append(tp.rows, columnCells)
}

func (tp *TablePrinter) PushHorizontalUnderlines() {
	tp.rows = append(tp.rows, tp.hotizontalUnderlines())
}

func (tp *TablePrinter) Print() {
	fmt.Printf(tp.assembleTable())
}

func (tp *TablePrinter) assembleTable() string {
	var tableString string
	headerString := tp.rowAsString(tp.headers)
	tableString += fmt.Sprintf("%s\n", colour.LightBlue(headerString))
	tableString += fmt.Sprintf("%s\n", tp.rowAsString(tp.hotizontalUnderlines()))
	for _, row := range tp.rows {
		tableString += fmt.Sprintf("%s\n", tp.rowAsString(row))
	}
	return tableString
}

func (tp *TablePrinter) rowAsString(row Row) string {
	var rowString string
	columnWidths := tp.columnWidths()
	for i, columnLabel := range row.columns {
		rowString += fmt.Sprintf("%-*s%s", columnWidths[i], columnLabel, gutter())
	}
	return strings.TrimSuffix(rowString, gutter())
}

func (tp *TablePrinter) hotizontalUnderlines() Row {
	var underlines = new(Row)
	for _, columnWidth := range tp.columnWidths() {
		underlines.columns = append(underlines.columns, strings.Repeat("─", columnWidth))
	}
	return *underlines
}

func (tp *TablePrinter) columnWidths() []int {
	var columnWidths []int

	for column, headerContent := range tp.headers.columns {
		colWidth := len(headerContent)
		for _, row := range tp.rows {
			cellContent := row.columns[column]
			colWidth = max(colWidth, len(cellContent))
		}
		columnWidths = append(columnWidths, colWidth)
	}

	return columnWidths
}

func gutter() string {
	return strings.Repeat(" ", gutterWidth)
}

// Max returns the larger of x or y.
func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}
