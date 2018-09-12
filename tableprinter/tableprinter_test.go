package tableprinter

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/colour"
)

func TestAssembleTable(t *testing.T) {
	tp := TablePrinter{
		headers: Row{[]string{"Email", "Name", "Address"}},
		rows: []Row{
			Row{[]string{"jane@example.com", "J.", "N/A"}},
			Row{[]string{"chat-wannamaker@example.com", "Chat", "Sheffield"}},
		},
	}

	want := fmt.Sprintf("%s\n", colour.LightBlue("Email                        Name  Address  "))
	want += fmt.Sprintf("───────────────────────────  ────  ─────────\n")
	want += fmt.Sprintf("jane@example.com             J.    N/A      \n")
	want += fmt.Sprintf("chat-wannamaker@example.com  Chat  Sheffield\n")

	got := tp.assembleTable()

	if got != want {
		t.Fatalf("Expected\n----\n%s\n----\n\nGot\n----\n%s\n----\n", want, got)
	}
}

func TestRowsAsString(t *testing.T) {
	t.Run("with only a header row", func(t *testing.T) {
		tp := TablePrinter{
			headers: Row{[]string{"Email", "Name", "Address"}},
		}

		want := "Email  Name  Address"
		got := tp.rowAsString(tp.headers)

		if got != want {
			t.Fatalf("Expected '%s', got '%s'", want, got)
		}
	})

	t.Run("with a row with a longer field than the header", func(t *testing.T) {
		tp := TablePrinter{
			headers: Row{[]string{"Email", "Name", "Address"}},
			rows: []Row{
				Row{[]string{"jane@example.com", "J.", "N/A"}},
			},
		}

		want := "Email             Name  Address"
		//       jane@example.com  J.    N/A
		got := tp.rowAsString(tp.headers)

		if got != want {
			t.Fatalf("Expected '%s', got '%s'", want, got)
		}

		//     `Email             Name  Address`
		want = "jane@example.com  J.    N/A    "

		got = tp.rowAsString(tp.rows[0])

		if got != want {
			t.Fatalf("Expected '%s', got '%s'", want, got)
		}
	})
}

func TestHorizontalUnderlines(t *testing.T) {
	t.Run("with only a header row", func(t *testing.T) {
		tp := TablePrinter{
			headers: Row{[]string{"Email", "Name", "Address"}},
		}

		//                Email    Name    Address
		want := Row{[]string{"─────", "────", "───────"}}
		got := tp.hotizontalUnderlines()

		if !testEqualRow(t, got, want) {
			t.Fatalf("Expected '%s', got '%s'", want, got)
		}
	})

	t.Run("with a row with a longer field than the header", func(t *testing.T) {
		tp := TablePrinter{
			headers: Row{[]string{"Email", "Name", "Address"}},
			rows: []Row{
				Row{[]string{"jane@example.com", "J.", "N/A"}},
			},
		}

		//                Email               Name    Address
		//                jane@example.com    J.      N/A
		want := Row{[]string{"────────────────", "────", "───────"}}
		got := tp.hotizontalUnderlines()

		if !testEqualRow(t, got, want) {
			t.Fatalf("Expected '%s', got '%s'", want, got)
		}
	})
}

func TestColumnWidths(t *testing.T) {
	t.Run("with only a header row", func(t *testing.T) {
		tp := TablePrinter{
			headers: Row{[]string{"1234", "12345", "123"}},
		}

		want := []int{4, 5, 3}
		got := tp.columnWidths()

		if !testEqualSliceInt(t, got, want) {
			t.Fatalf("Expected %v, got %v", want, got)
		}
	})

	t.Run("with only a header row", func(t *testing.T) {
		tp := TablePrinter{
			headers: Row{[]string{"1234", "12345", "123"}},
			rows: []Row{
				Row{[]string{"123456", "123", "1234567"}},
			},
		}

		want := []int{6, 5, 7}
		got := tp.columnWidths()

		if !testEqualSliceInt(t, got, want) {
			t.Errorf("Expected %v, got %v", want, got)
		}
	})
}

// Equal tells whether a and b contain the same elements.
// A nil argument is equivalent to an empty slice.
func testEqualSliceInt(t *testing.T, a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// Equal tells whether a and b contain the same elements.
// A nil argument is equivalent to an empty slice.
func testEqualRow(t *testing.T, a, b Row) bool {
	if len(a.columns) != len(b.columns) {
		return false
	}
	for i, v := range a.columns {
		if v != b.columns[i] {
			return false
		}
	}
	return true
}
