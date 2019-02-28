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
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func TestEncryptSecret(t *testing.T) {
	secret := "Secret message!"

	pgpKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey4, "test4")
	if err != nil {
		t.Fatalf("error loading private key: %s", err)
	}

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

func (m mockReadFile) ReadFileMaxBytes(filename string, maxBytes int64) ([]byte, error) {
	return m.readFileBytes, m.readFileError
}

type mockScanStdin struct {
	scanMessage string
	scanError   error
}

func (m *mockScanStdin) scanUntilEOF() (string, error) {
	return m.scanMessage, m.scanError
}

func TestGetSecretFromFile(t *testing.T) {
	t.Run("returns the file contents as string", func(t *testing.T) {
		fileReader := mockReadFile{
			readFileError: nil,
			readFileBytes: []byte("hello"),
		}

		secret, err := getSecretFromFile("/fake/filename", fileReader)
		assert.ErrorIsNil(t, err)
		assert.Equal(t, "hello", secret)
	})

	t.Run("fails if file contained disallowed runes", func(t *testing.T) {
		fileReader := mockReadFile{
			readFileBytes: []byte(colour.Warning("text with colour")),
		}

		_, err := getSecretFromFile("/fake/filename", fileReader)
		expectedErr := fmt.Errorf("/fake/filename contains disallowed characters")
		assert.Equal(t, expectedErr, err)

	})

	t.Run("fails if file isn't valid utf-8", func(t *testing.T) {
		fileReader := mockReadFile{
			readFileBytes: []byte{255},
		}

		_, err := getSecretFromFile("/fake/filename", fileReader)
		expectedErr := fmt.Errorf("/fake/filename contains disallowed characters")
		assert.Equal(t, expectedErr, err)
	})

	t.Run("passes up errors from ReadFile", func(t *testing.T) {
		fileReader := mockReadFile{
			readFileError: fmt.Errorf("permission denied"),
		}

		_, err := getSecretFromFile("/fake/filename", fileReader)
		expectedErr := fmt.Errorf("error reading file: permission denied")
		assert.Equal(t, expectedErr, err)
	})

	t.Run("returns error if file is empty", func(t *testing.T) {
		fileReader := mockReadFile{
			readFileError: nil,
			readFileBytes: []byte(""),
		}

		_, err := getSecretFromFile("/fake/filename", fileReader)
		expectedErr := fmt.Errorf("/fake/filename is empty")
		assert.Equal(t, expectedErr, err)
	})

}

func TestReadUpTo(t *testing.T) {
	t.Run("input 4 bytes, maxLength 5 should return 4 bytes", func(t *testing.T) {
		input := []byte("1234")
		gotBytes, gotErr := readUpTo(bytes.NewBuffer(input), 5)
		assert.ErrorIsNil(t, gotErr)
		assert.Equal(t, input, gotBytes)
	})

	t.Run("input 5 bytes, maxLength 5 should return 5 bytes", func(t *testing.T) {
		input := []byte("12345")
		gotBytes, gotErr := readUpTo(bytes.NewBuffer(input), 5)
		assert.ErrorIsNil(t, gotErr)
		assert.Equal(t, input, gotBytes)
	})

	t.Run("input 6 bytes, maxLength 5 should return error: too much data", func(t *testing.T) {
		input := []byte("123456")
		_, gotErr := readUpTo(bytes.NewBuffer(input), 5)
		assert.Equal(t, gotErr, errTooMuchData)
	})

}

func TestGetSecretFromStdin(t *testing.T) {
	t.Run("returns stdin content with nil error for valid message", func(t *testing.T) {
		stdinScanner := &mockScanStdin{
			scanMessage: "line 1\nline 2\nline 3",
		}

		result, err := getSecretFromStdin(stdinScanner)
		assert.ErrorIsNil(t, err)
		assert.Equal(t, stdinScanner.scanMessage, result)
	})

	t.Run("returns error if message is only spaces", func(t *testing.T) {
		stdinScanner := &mockScanStdin{
			scanMessage: "        ",
		}

		_, err := getSecretFromStdin(stdinScanner)
		expectedErr := fmt.Errorf("empty message")
		assert.Equal(t, expectedErr, err)
	})

	t.Run("returns error if message is only newlines", func(t *testing.T) {
		stdinScanner := &mockScanStdin{
			scanMessage: "\n\n\n",
		}

		_, err := getSecretFromStdin(stdinScanner)
		expectedErr := fmt.Errorf("empty message")
		assert.Equal(t, expectedErr, err)

	})

	t.Run("returns error if stdin contained disallowed runes", func(t *testing.T) {
		stdinScanner := &mockScanStdin{
			scanMessage: colour.Warning("text with colour"),
		}

		_, err := getSecretFromStdin(stdinScanner)
		expectedErr := errSecretContainsDisallowedCharacters
		assert.Equal(t, expectedErr, err)

	})

	t.Run("returns error if stdin isn't valid utf-8", func(t *testing.T) {
		stdinScanner := &mockScanStdin{
			scanMessage: string([]byte{255}),
		}

		_, err := getSecretFromStdin(stdinScanner)
		expectedErr := errSecretContainsDisallowedCharacters
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
