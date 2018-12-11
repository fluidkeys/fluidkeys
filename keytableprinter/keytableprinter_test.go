package keytableprinter

import (
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/status"
)

func TestMakeTableRows(t *testing.T) {
	pgpKey, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey2)
	if err != nil {
		t.Fatalf("failed to load example PgpKey: %v", err)
	}

	t.Run("with example pgp key", func(t *testing.T) {
		makeTableRows(
			[]KeyWithWarnings{
				KeyWithWarnings{Key: pgpKey},
			},
		)
	})

	t.Run("with empty slice of keys", func(t *testing.T) {
		makeTableRows(
			[]KeyWithWarnings{},
		)
	})

}

func TestMakeRowsFromColumns(t *testing.T) {
	columns := []column{
		column{"Jane", "Jill"},
		column{"One", "Two", "Three", "Four"},
		column{"", "Hello"},
	}

	got := makeRowsFromColumns(columns)
	want := []row{
		row{"Jane", "One", ""},
		row{"Jill", "Two", "Hello"},
		row{"", "Three", ""},
		row{"", "Four", ""},
	}

	AssertEqualCells(t, want, got)
}

func TestMakeStringsFromRows(t *testing.T) {
	t.Run("with unformatted strings", func(t *testing.T) {
		rows := []row{
			row{"Name", "Age", "Location"},
			row{divider, divider, divider},
			row{"Gillian", "45", ""},
			row{divider, divider, divider},
			row{"Jill", "76", "Sheffield"},
			row{divider, divider, divider},
			row{"", "23", ""},
			row{"", "12", ""},
		}

		got := makeStringsFromRows(rows)
		want := []string{
			"Name     Age  Location ",
			"───────  ───  ─────────",
			"Gillian  45            ",
			"───────  ───  ─────────",
			"Jill     76   Sheffield",
			"───────  ───  ─────────",
			"         23            ",
			"         12            ",
		}

		assert.AssertEqualSliceOfStrings(t, want, got)
	})

	t.Run("with coloured strings", func(t *testing.T) {
		rows := []row{
			row{colour.TableHeader("Name"), colour.TableHeader("Age")},
			row{divider, divider},
			row{"Gillian", "45"},
		}

		got := makeStringsFromRows(rows)
		want := []string{
			colour.TableHeader("Name") + "     " + colour.TableHeader("Age"),
			"───────  ───",
			"Gillian  45 ",
		}

		assert.AssertEqualSliceOfStrings(t, want, got)
	})
}

func TestGetColumnWidths(t *testing.T) {
	t.Run("with sensible rows", func(t *testing.T) {
		rows := []row{
			row{"1234", "12", "123"},
			row{"12", "123456", "1"},
			row{"123", "123", "12"},
		}

		want := []int{4, 6, 3}
		got := getColumnWidths(rows)

		assert.AssertEqualSliceOfInts(t, want, got)
	})

	t.Run("with empty rows", func(t *testing.T) {
		rows := []row{}

		want := []int{}
		got := getColumnWidths(rows)

		assert.AssertEqualSliceOfInts(t, want, got)
	})
}

func TestMaxInSlice(t *testing.T) {
	integers := []int{2, 5, 10, 1, -9, 7}

	want := 10
	got := maxInSlice(integers)

	if got != want {
		t.Fatalf("Expected '%v', got '%v'", want, got)
	}
}

func TestKeyStatus(t *testing.T) {

	pgpKey, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey2)
	if err != nil {
		t.Fatalf("failed to load example PgpKey: %v", err)
	}

	want := []string{colour.Success("Good ✔")}
	got := keyStatus(*pgpKey, []status.KeyWarning{})

	assert.AssertEqualSliceOfStrings(t, want, got)
}

// AssertEqualCells compares two string slices and calls t.Fatalf
// with a message if they differ.
func AssertEqualCells(t *testing.T, expected, got [][]string) {
	t.Helper()
	if len(expected) != len(got) {
		t.Fatalf("expected length %d, got %d. expected: %v, got: %v",
			len(expected), len(got), expected, got)
	}
	for i := range expected {
		assert.AssertEqualSliceOfStrings(t, expected[i], got[i])
	}
}
