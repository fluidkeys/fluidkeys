package gpgwrapper

import "testing"

func TestParseGPGOutputVersion(t *testing.T) {
	assert_parses_equal(t, "foo\ngpg (GnuPG) 2.2.4\nbar", "2.2.4")
	assert_parses_equal(t, "foo\ngpg (GnuPG/MacGPG2) 2.2.8\nbar", "2.2.8")
	assert_parses_equal(t, "foo\ngpg (GnuPG/MacGPG2) 111.222.333\nbar", "111.222.333")
}

func TestReturnsErrorForBadGpgOutput(t *testing.T) {
	_, err := parseVersionString("bad output")

	if err == nil {
		t.Errorf("Test failed, no error returned")
	}

	expectedError := "version string not found in GPG output"

	if err.Error() != expectedError {
		t.Errorf("Test failed, expected error %s, got '%s'", expectedError, err.Error())
	}
}

func assert_parses_equal(t *testing.T, gpgOutput string, expected string) {
	actual, err := parseVersionString(gpgOutput)

	if err != nil {
		t.Errorf("Test failed, returned error %s", err)
	}

	if actual != expected {
		t.Errorf("Test failed, expected '%s', got '%s'", expected, actual)
	}
}
