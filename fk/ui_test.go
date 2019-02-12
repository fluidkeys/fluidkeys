package fk

import (
	"fmt"
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

func TestFormatFirstTwentyLines(t *testing.T) {
	t.Run("with content of less than 20 lines", func(t *testing.T) {
		content := "line 1\nline 2\nline 3\n"
		got, truncated := formatFirstTwentyLines(content)
		assert.Equal(t, content, got)
		assert.Equal(t, false, truncated)
	})

	t.Run("with content less than 20 lines, last missing a new line", func(t *testing.T) {
		content := "line 1\nline 2"
		got, truncated := formatFirstTwentyLines(content)
		assert.Equal(t, "line 1\nline 2\n", got)
		assert.Equal(t, false, truncated)
	})

	t.Run("with content of exactly 19 lines", func(t *testing.T) {
		content := makeNLines(t, 19)
		got, truncated := formatFirstTwentyLines(content)
		assert.Equal(t, content, got)
		assert.Equal(t, false, truncated)
	})

	t.Run("with content of exactly 20 lines, ending with a new line", func(t *testing.T) {
		content := makeNLines(t, 20)
		got, truncated := formatFirstTwentyLines(content)
		assert.Equal(t, content, got)
		assert.Equal(t, false, truncated)
	})

	t.Run("with 20 lines where the last is missing a trailing new line", func(t *testing.T) {
		content := makeNLines(t, 19) + "last missing new line"
		got, truncated := formatFirstTwentyLines(content)
		assert.Equal(t, makeNLines(t, 19)+"last missing new line\n", got)
		assert.Equal(t, false, truncated)
	})

	t.Run("with content of exactly 21 lines", func(t *testing.T) {
		content := makeNLines(t, 21)
		got, truncated := formatFirstTwentyLines(content)
		assert.Equal(t, makeNLines(t, 20), got)
		assert.Equal(t, true, truncated)
	})

	t.Run("with content of a hundred lines", func(t *testing.T) {
		content := makeNLines(t, 100)
		got, truncated := formatFirstTwentyLines(content)
		assert.Equal(t, makeNLines(t, 20), got)
		assert.Equal(t, true, truncated)
	})

	t.Run("with content buried beneath lots of new lines", func(t *testing.T) {
		content := strings.Repeat("\n", 25) + "some content"
		got, truncated := formatFirstTwentyLines(content)
		assert.Equal(t, strings.Repeat("\n", 20), got)
		assert.Equal(t, true, truncated)
	})
}

func makeNLines(t *testing.T, numberOfLines int) string {
	t.Helper()

	lines := []string{}
	for i := 0; i < numberOfLines; i++ {
		lines = append(lines, fmt.Sprintf("line %d", i+1))
	}
	return strings.Join(lines, "\n") + "\n"
}
