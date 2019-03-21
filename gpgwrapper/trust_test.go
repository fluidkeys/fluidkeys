package gpgwrapper

import (
	"fmt"
	"strings"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
)

func TestTrustUltimately(t *testing.T) {

	gpg := makeGpgWithTempHome(t)
	gpg.ImportArmoredKey(exampledata.ExamplePublicKey2)

	stdout, _, err := gpg.run("", "--list-keys", "--with-colons")
	assert.NoError(t, err)

	// ensure we start off with "unknown" validity.
	// see "Field 2 - Validity" in https://github.com/gpg/gnupg/blob/master/doc/DETAILS
	if !strings.Contains(stdout, "uid:-:") {
		t.Fatalf("expected gpg to show unknown validity `uid:-:` but got:\n%s\n", stdout)
	}

	t.Run("sets ownertrust to ultimate", func(t *testing.T) {
		err := gpg.TrustUltimately(exampledata.ExampleFingerprint2)
		assert.NoError(t, err)

		stdout, _, err := gpg.run("", "--list-keys", "--with-colons")
		assert.NoError(t, err)
		fmt.Println(stdout)
		if !strings.Contains(stdout, "uid:u:") { // 'u' means ultimate
			t.Fatalf("expected gpg to show ultimate validity `uid:u:`, got:\n%s\n", stdout)
		}

	})

	t.Run("with a non existent fingerprint", func(t *testing.T) {
		err := gpg.TrustUltimately(exampledata.ExampleFingerprint3)
		assert.GotError(t, err)
		assert.Equal(t, fmt.Errorf("no such key 7C18DE4DE47813568B243AC8719BD63EF03BDC20"), err)
	})

}
