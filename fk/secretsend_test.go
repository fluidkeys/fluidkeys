package fk

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func TestEncryptSecret(t *testing.T) {
	secret := "Secret message!"

	pgpKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey4, "test4")
	if err != nil {
		t.Fatalf("error loading private key: %s", err)
	}

	t.Run("containing a disallowed rune", func(t *testing.T) {
		secretWithDisallowedRune := "\x1b[40mBlocked secret message!\x1b[0m"

		_, err := encryptSecret(secretWithDisallowedRune, "", pgpKey)
		assert.ErrorIsNotNil(t, err)
	})

	t.Run("with an empty filename", func(t *testing.T) {
		armoredEncryptedSecret, err := encryptSecret(secret, "", pgpKey)
		assert.ErrorIsNil(t, err)

		messageDetails := decryptMessageDetails(armoredEncryptedSecret, pgpKey, t)
		assertMessageBodyMatchesSecretContent(messageDetails.UnverifiedBody, secret, t)
		assert.Equal(t, "_CONSOLE", messageDetails.LiteralData.FileName)
		if messageDetails.LiteralData.ForEyesOnly() != true {
			t.Fatalf("expected secret to be For Eyes Only, but isn't")
		}
	})

	t.Run("with a filename", func(t *testing.T) {
		armoredEncryptedSecret, err := encryptSecret(secret, "secret.txt", pgpKey)
		assert.ErrorIsNil(t, err)

		messageDetails := decryptMessageDetails(armoredEncryptedSecret, pgpKey, t)
		assertMessageBodyMatchesSecretContent(messageDetails.UnverifiedBody, secret, t)
		assert.Equal(t, "secret.txt", messageDetails.LiteralData.FileName)
		if messageDetails.LiteralData.ForEyesOnly() == true {
			t.Fatalf("expected secret not to be For Eyes Only, but is")
		}
	})

}

type mockReadFile struct {
	readFileBytes []byte
	readFileError error
}

func (m mockReadFile) ReadFile(filename string) ([]byte, error) {
	return m.readFileBytes, m.readFileError
}

type mockYesNoPrompter struct {
	answer bool
}

func (m mockYesNoPrompter) promptYesNo(question string, defaultAnswer string, key *pgpkey.PgpKey) bool {
	return m.answer
}

func TestGetSecretFromFile(t *testing.T) {
	t.Run("returns the file contents as string", func(t *testing.T) {
		fileReader := mockReadFile{
			readFileError: nil,
			readFileBytes: []byte("hello"),
		}

		prompter := mockYesNoPrompter{
			answer: true,
		}

		secret, err := getSecretFromFile("/fake/filename", fileReader, prompter)
		assert.ErrorIsNil(t, err)
		assert.Equal(t, "hello", secret)
	})

	t.Run("passes up errors from ReadFile", func(t *testing.T) {
		fileReader := mockReadFile{
			readFileError: fmt.Errorf("permission denied"),
		}

		_, err := getSecretFromFile("/fake/filename", fileReader, nil)
		expectedErr := fmt.Errorf("error reading file: permission denied")
		assert.Equal(t, expectedErr, err)
	})

	t.Run("returns error if file is empty", func(t *testing.T) {
		fileReader := mockReadFile{
			readFileError: nil,
			readFileBytes: []byte(""),
		}

		_, err := getSecretFromFile("/fake/filename", fileReader, nil)
		expectedErr := fmt.Errorf("/fake/filename is empty")
		assert.Equal(t, expectedErr, err)
	})

	t.Run("returns error if user answers no", func(t *testing.T) {

		fileReader := mockReadFile{
			readFileError: nil,
			readFileBytes: []byte("hello"),
		}

		prompter := mockYesNoPrompter{
			answer: false,
		}

		_, err := getSecretFromFile("/fake/filename", fileReader, prompter)
		expectedErr := fmt.Errorf("didn't accept prompt to send file")
		assert.Equal(t, expectedErr, err)
	})

}

func decryptMessageDetails(armoredEncryptedSecret string, pgpKey *pgpkey.PgpKey, t *testing.T) *openpgp.MessageDetails {
	t.Helper()

	buf := strings.NewReader(armoredEncryptedSecret)

	block, err := armor.Decode(buf)
	if err != nil {
		t.Fatalf("error decoding armor: %s", err)
	}

	var keyRing openpgp.EntityList = []*openpgp.Entity{&pgpKey.Entity}

	messageDetails, err := openpgp.ReadMessage(block.Body, keyRing, nil, nil)
	if err != nil {
		t.Fatalf("error rereading message: %s", err)
	}

	return messageDetails
}

func assertMessageBodyMatchesSecretContent(unverifiedBody io.Reader, secret string, t *testing.T) {
	t.Helper()

	messageBuf := bytes.NewBuffer(nil)
	_, err := io.Copy(messageBuf, unverifiedBody)
	if err != nil {
		t.Fatalf("error rereading message: %s", err)
	}
	if !bytes.Equal([]byte(secret), messageBuf.Bytes()) {
		t.Fatalf("recovered message incorrect got '%s', want '%s'", messageBuf.Bytes(), secret)
	}
}
