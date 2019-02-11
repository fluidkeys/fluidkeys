package fk

import (
	"strings"
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

		t.Run("with no file extension", func(t *testing.T) {
			divider := formatFileDivider("example1234567890123456789012345678901234567890123456789012345678901234567890")
			assert.Equal(
				t,
				"── "+colour.File("example123456789012345678901234567890123456789012345678901234567890123456…")+" ──",
				divider,
			)
			assert.Equal(t, 80, utf8.RuneCountInString(colour.StripAllColourCodes(divider)))
		})

		t.Run("filename is 1 less than maxFilenameLength", func(t *testing.T) {
			// should not be truncated
			filename := strings.Repeat("a", maxFilenameLength-1)
			divider := formatFileDivider(filename)

			assert.Equal(
				t,
				"── "+colour.File(filename)+" ───", // note: 3 runes on right
				divider,
			)
			assert.Equal(t, 80, utf8.RuneCountInString(colour.StripAllColourCodes(divider)))
		})

		t.Run("filename is exactly maxFilenameLength", func(t *testing.T) {
			// should not be truncated
			filename := strings.Repeat("a", maxFilenameLength)
			divider := formatFileDivider(filename)

			assert.Equal(
				t,
				"── "+colour.File(filename)+" ──",
				divider,
			)
			assert.Equal(t, 80, utf8.RuneCountInString(colour.StripAllColourCodes(divider)))
		})

		t.Run("filename is 1 more than maxFilenameLength", func(t *testing.T) {
			filename := strings.Repeat("a", maxFilenameLength+1)
			divider := formatFileDivider(filename)

			assert.Equal(
				t,
				"── "+colour.File(filename[0:maxFilenameLength-1]+"…")+" ──",
				divider,
			)
			assert.Equal(t, 80, utf8.RuneCountInString(colour.StripAllColourCodes(divider)))
		})

		t.Run("filename is 100 more than maxFilenameLength", func(t *testing.T) {
			filename := strings.Repeat("a", maxFilenameLength+100)
			divider := formatFileDivider(filename)

			assert.Equal(
				t,
				"── "+colour.File(filename[0:maxFilenameLength-1]+"…")+" ──",
				divider,
			)
			assert.Equal(t, 80, utf8.RuneCountInString(colour.StripAllColourCodes(divider)))
		})
	})

}
