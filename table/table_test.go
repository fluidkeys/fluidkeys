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
)

func TestFormatTableStringsFromRows(t *testing.T) {
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

		got := formatTableStringsFromRows(rows)
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

		got := formatTableStringsFromRows(rows)
		want := []string{
			colour.TableHeader("Name") + "     " + colour.TableHeader("Age"),
			"───────  ───",
			"Gillian  45 ",
		}

		assert.AssertEqualSliceOfStrings(t, want, got)
	})
}
