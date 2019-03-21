package gpgwrapper

import (
	"fmt"
	"strings"

	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
)

// TrustUltimately sets the ownertrust level of the given key to "ultimate", meaning
// "I trust this key to correctly certify other keys".
// At the very least we set our *own* keys' ownertrust to ultimate so our own certifications
// are valid.
func (g *GnuPG) TrustUltimately(fingerprint fpr.Fingerprint) error {
	trustCommands := "trust\n5\ny\n"
	_, stderr, err := g.run(trustCommands, "--command-fd=0", "--edit-key", fingerprint.Hex())

	if err != nil {
		if strings.Contains(stderr, noPublicKey) {
			return fmt.Errorf("no such key " + fingerprint.Hex())
		}
		return err
	}

	return nil
}
