package main

import (
	"bufio"
	"strings"
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
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

func TestPromptForInput(t *testing.T) {
	t.Run("reads an input", func(t *testing.T) {
		typedInput := "Ian\n"
		expectedReturn := "Ian"

		fakeStdin := bufio.NewReader(strings.NewReader(typedInput))

		actualReturn := promptForInputWithPipes(" [name] : ", fakeStdin)

		if actualReturn != expectedReturn {
			t.Errorf("expected '%s', got '%s'", expectedReturn, actualReturn)
		}
	})
}

func TestGetFluidkeysDirectory(t *testing.T) {
	dir, err := getFluidkeysDirectory()

	if err != nil {
		t.Fatalf("failed to get fluidkeys directory: %v", err)
	}

	t.Logf(dir)
}

func TestPromptForWhichGpgKey(t *testing.T) {
	t.Run("pluarlises the word key in the sentence", func(t *testing.T) {
		secretKeyListings := []gpgwrapper.SecretKeyListing{
			exampleSecretKey,
		}

		actualReturn := formatListedKeysForImportingFromGpg(secretKeyListings)
		actualFirstLineReturn := strings.Split(actualReturn, "\n")[0]
		expectedFirstLineReturn := "Found 1 key in GnuPG:"

		if actualFirstLineReturn != expectedFirstLineReturn {
			t.Errorf("expected '%s', got '%s'", expectedFirstLineReturn, actualFirstLineReturn)
		}

		secretKeyListings = []gpgwrapper.SecretKeyListing{
			exampleSecretKey,
			exampleSecretKey,
			exampleSecretKey,
		}

		actualReturn = formatListedKeysForImportingFromGpg(secretKeyListings)
		actualFirstLineReturn = strings.Split(actualReturn, "\n")[0]
		expectedFirstLineReturn = "Found 3 keys in GnuPG:"

		if actualFirstLineReturn != expectedFirstLineReturn {
			t.Errorf("expected '%s', got '%s'", expectedFirstLineReturn, actualFirstLineReturn)
		}
	})

	t.Run("prints a correctly formatted secret key", func(t *testing.T) {
		secretKeyListings := []gpgwrapper.SecretKeyListing{
			gpgwrapper.SecretKeyListing{
				Fingerprint: "BBBB BBBB BBBB BBBB BBBB  BBBB BBBB BBBB BBBB BBBB",
				Uids: []string{
					"Chat Wannamaker<chat2@example.com>",
					"Chat Rulez<chat3@example.com>",
				},
				Created: time.Date(2012, 06, 15, 12, 00, 00, 00, time.UTC),
			},
		}

		gotReturn := formatListedKeysForImportingFromGpg(secretKeyListings)
		expectedReturn := `Found 1 key in GnuPG:

` + colour.LightBlue("1.") + `  BBBB BBBB BBBB BBBB BBBB  BBBB BBBB BBBB BBBB BBBB
    Created on 15 June 2012
      Chat Wannamaker<chat2@example.com>
      Chat Rulez<chat3@example.com>

`

		if gotReturn != expectedReturn {
			t.Errorf("expected '%s', got '%s'", expectedReturn, gotReturn)
		}
	})
}

var exampleSecretKey = gpgwrapper.SecretKeyListing{
	Fingerprint: "BBBB BBBB BBBB BBBB BBBB  BBBB BBBB BBBB BBBB BBBB",
	Uids: []string{
		"Chat Wannamaker<chat2@example.com>",
		"Chat Rulez<chat3@example.com>",
	},
	Created: time.Now(),
}
