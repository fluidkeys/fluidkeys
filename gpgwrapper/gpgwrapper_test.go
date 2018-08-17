package gpgwrapper

import (
	"errors"
	"testing"
)

func TestParseGPGOutputVersion(t *testing.T) {

	t.Run("test GPG output from Ubuntu", func(t *testing.T) {
		gpgOutput := "foo\ngpg (GnuPG) 2.2.4\nbar"
		assert_parses_version_correctly(t, gpgOutput, "2.2.4")
	})

	t.Run("test GPG output from macOS", func(t *testing.T) {
		gpgOutput := "foo\ngpg (GnuPG/MacGPG2) 2.2.8\nbar"
		assert_parses_version_correctly(t, gpgOutput, "2.2.8")
	})

	t.Run("test long version numbers", func(t *testing.T) {
		gpgOutput := "foo\ngpg (GnuPG/MacGPG2) 111.222.333\nbar"
		assert_parses_version_correctly(t, gpgOutput, "111.222.333")
	})

	t.Run("test output not containing a version number", func(t *testing.T) {
		gpgOutput := "foo\ngpg\nbar"
		_, err := parseVersionString(gpgOutput)
		want := errors.New("version string not found in GPG output")
		assertError(t, err, want)
	})
}

func assert_parses_version_correctly(t *testing.T, gpgOutput string, want string) {
	t.Helper()
	got, err := parseVersionString(gpgOutput)

	if err != nil {
		t.Errorf("Test failed, returned error %s", err)
	}

	if got != want {
		t.Errorf("Test failed, expected '%s', got '%s'", want, got)
	}
}

func assertError(t *testing.T, got error, want error) {
	t.Helper()

	if got == nil {
		t.Fatal("wanted an error but didnt get one")
	}

	if got != want {
		t.Errorf("wanted '%s', got '%s'", got, want)
	}
}
