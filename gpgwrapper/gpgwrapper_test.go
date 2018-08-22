package gpgwrapper

import (
	"strings"
	"testing"
)

const ExamplePublicKey string = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
We0fI5qRW/I=
=MZEv
-----END PGP PUBLIC KEY BLOCK-----`

func TestParseGPGOutputVersion(t *testing.T) {

	t.Run("test GPG output from Ubuntu", func(t *testing.T) {
		gpgOutput := "foo\ngpg (GnuPG) 2.2.4\nbar"
		assertParsesVersionCorrectly(t, gpgOutput, "2.2.4")
	})

	t.Run("test GPG output from macOS", func(t *testing.T) {
		gpgOutput := "foo\ngpg (GnuPG/MacGPG2) 2.2.8\nbar"
		assertParsesVersionCorrectly(t, gpgOutput, "2.2.8")
	})

	t.Run("test long version numbers", func(t *testing.T) {
		gpgOutput := "foo\ngpg (GnuPG/MacGPG2) 111.222.333\nbar"
		assertParsesVersionCorrectly(t, gpgOutput, "111.222.333")
	})

	t.Run("test output not containing a version number", func(t *testing.T) {
		gpgOutput := "foo\ngpg\nbar"
		_, err := parseVersionString(gpgOutput)
		assertError(t, err, ErrNoVersionStringFound)
	})
}

func TestRunningGPG(t *testing.T) {
	t.Run("with valid arguments", func(t *testing.T) {
		arguments := "--version"
		_, err := runGpg(arguments)
		assertNoError(t, err)
	})

	t.Run("with invalid arguments", func(t *testing.T) {
		arguments := "--foo"
		want := ErrProblemExecutingGPG("gpg: invalid option \"--foo\"\n", arguments)
		_, err := runGpg(arguments)
		assertError(t, err, want)
	})
}

func TestRunGpgWithStdin(t *testing.T) {
	t.Run("with a valid public key", func(t *testing.T) {
		successMessages := []string{
			"gpg: key 0x0BBD7E7E5B85C8D3: public key \"test@example.com\" imported",
			"gpg: key 0x0BBD7E7E5B85C8D3: \"test@example.com\" not changed",
		}

		arguments := []string{"--import"}

		output, err := runGpgWithStdin(ExamplePublicKey, arguments...)

		if err != nil {
			t.Errorf("Test failed, returned error %s", err)
		}

		var sawSuccessMessage = false

		for _, successMessage := range successMessages {
			if strings.Contains(output, successMessage) {
				sawSuccessMessage = true
				break
			}
		}

		if !sawSuccessMessage {
			t.Errorf("GPGs output '%s' did not contain any success messages", output)
		}
	})
}

func assertParsesVersionCorrectly(t *testing.T, gpgOutput string, want string) {
	t.Helper()
	got, err := parseVersionString(gpgOutput)

	if err != nil {
		t.Errorf("Test failed, returned error %s", err)
	}

	if got != want {
		t.Errorf("Test failed, wanted '%s', got '%s'", want, got)
	}
}

func assertError(t *testing.T, got error, want error) {
	t.Helper()

	if got == nil {
		t.Fatal("wanted an error but didnt get one")
	}

	if got.Error() != want.Error() {
		t.Errorf("wanted '%s', got '%s'", want, got)
	}
}

func assertNoError(t *testing.T, got error) {
	t.Helper()
	if got != nil {
		t.Fatalf("got an error but didnt want one '%s'", got)
	}
}
