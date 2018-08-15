package main

import (
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	t.Run("doesn't generate empty string", func(t *testing.T) {
		actual := generatePassword(6, ".").AsString()
		if actual == "" {
			t.Errorf("password was empty")
		}

	})

	t.Run("make 5 word password", func(t *testing.T) {
		wordCount := 5
		password := generatePassword(wordCount, ".").AsString()
		words := strings.Split(password, ".")

		if len(words) != wordCount {
			t.Errorf("asked for '%d' word password, got password '%s'", wordCount, password)
		}
	})

	t.Run("make 6 word password", func(t *testing.T) {
		wordCount := 6
		password := generatePassword(wordCount, ".").AsString()
		words := strings.Split(password, ".")

		if len(words) != wordCount {
			t.Errorf("asked for '%d' word password, got password '%s'", wordCount, password)
		}
	})

	t.Run("use hyphen separator", func(t *testing.T) {
		wordCount := 6
		password := generatePassword(wordCount, "-").AsString()
		numberOfHyphens := strings.Count(password, "-")

		if numberOfHyphens != 5 {
			t.Errorf("asked for '-' separator, got password '%s'", password)
		}
	})
}
