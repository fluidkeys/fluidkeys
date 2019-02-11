package fk

import (
	"testing"
	"unicode/utf8"

	"github.com/fluidkeys/fluidkeys/colour"

	"github.com/fluidkeys/fluidkeys/assert"
)

func TestFormatFileDivider(t *testing.T) {
	t.Run("with no filename provided", func(t *testing.T) {
		divider := formatFileDivider("")
		assert.Equal(
			t,
			"────────────────────────────────────────────────────────────────────────────────",
			divider,
		)
		assert.Equal(t, 80, utf8.RuneCountInString(colour.StripAllColourCodes(divider)))
	})

	t.Run("with a short filename provided", func(t *testing.T) {
		divider := formatFileDivider("example.txt")
		assert.Equal(
			t,
			"── "+colour.File("example.txt")+
				" ─────────────────────────────────────────────────────────────────",
			divider,
		)
		assert.Equal(t, 80, utf8.RuneCountInString(colour.StripAllColourCodes(divider)))
	})

	t.Run("with a long filename provided", func(t *testing.T) {
		divider := formatFileDivider("example1234567890123456789012345678901234567890123456789012345678901234567890.txt")
		assert.Equal(
			t,
			"── "+
				colour.File("example12345678901234567890123456789012345678901234567890123456789012….txt")+
				" ──",
			divider,
		)
		assert.Equal(t, 80, utf8.RuneCountInString(colour.StripAllColourCodes(divider)))
	})
}
