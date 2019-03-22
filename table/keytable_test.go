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
