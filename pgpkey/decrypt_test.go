package pgpkey

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/fluidkeys/exampledata"
)

func TestDecryptArmoredToString(t *testing.T) {
	pgpKey, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey4, "test4")
	if err != nil {
		t.Fatalf("error loading private key: %s", err)
	}

	t.Run("returns an error if the secret contains disallowed runes", func(t *testing.T) {
		message := "\x1b[41m Red \007 Bell \x1b[0m Reset"

		encryptedMessage := encryptMessage(message, pgpKey, false, t)

		_, _, err := pgpKey.DecryptArmoredToString(encryptedMessage)

		assert.Equal(t, fmt.Errorf("secret contains disallowed characters"), err)
	})

	t.Run("returns an error if message is binary", func(t *testing.T) {
		message := "\x1b[41m Red \007 Bell \x1b[0m Reset"

		encryptedMessage := encryptMessage(message, pgpKey, true, t)

		_, _, err := pgpKey.DecryptArmoredToString(encryptedMessage)

		assert.Equal(t, fmt.Errorf("encrypted binaries not allowed"), err)
	})
}

func encryptMessage(secret string, pgpKey *PgpKey, isBinary bool, t *testing.T) string {
	t.Helper()

	buffer := bytes.NewBuffer(nil)
	message, err := armor.Encode(buffer, "PGP MESSAGE", nil)
	if err != nil {
		t.Fatalf("error encoding empty pgp message: %s", err)
	}

	pgpWriteCloser, err := openpgp.Encrypt(
		message,
		[]*openpgp.Entity{&pgpKey.Entity},
		nil,
		&openpgp.FileHints{
			IsBinary: isBinary,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("error armor encrypting message: %s", err)
	}

	if _, err = pgpWriteCloser.Write([]byte(secret)); err != nil {
		t.Fatalf("error writing armor encryped message: %s", err)
	}

	pgpWriteCloser.Close()
	message.Close()
	return buffer.String()
}
