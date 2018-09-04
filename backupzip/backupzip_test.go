package backupzip

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"
)

func TestMakeBackupFile(t *testing.T) {
	zipData := bytes.NewBuffer(nil)
	WriteZipData(zipData, exampleSlug, examplePublicKey, examplePrivateKey, exampleRevocationCert)
	readerAt := bytes.NewReader(zipData.Bytes())
	zipReader, err := zip.NewReader(readerAt, int64(len(zipData.Bytes())))

	if err != nil {
		t.Errorf("zip.NewReader failed: %v", err)
		return
	}

	t.Run("generated ZIP file contains correct filenames", func(t *testing.T) {
		var gotFilenames []string

		for _, f := range zipReader.File {
			gotFilenames = append(gotFilenames, f.Name)
		}

		wantFilenames := []string{
			"2018-01-15-test-example-com-FAKEFINGERPRINT.public.txt",
			"2018-01-15-test-example-com-FAKEFINGERPRINT.private.encrypted.txt",
			"2018-01-15-test-example-com-FAKEFINGERPRINT.revoke.txt",
		}

		assertStringSlicesEqual(t, wantFilenames, gotFilenames)
	})

	t.Run("contents of ZIP file is correct", func(t *testing.T) {
		fileContents := make(map[string][]byte)

		for _, f := range zipReader.File {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("failed to get contents of file in ZIP `%s`", f.Name)
			}

			fileBuf := bytes.NewBuffer(nil)
			io.Copy(fileBuf, rc)
			fileContents[f.Name] = fileBuf.Bytes()
		}
		assertEqual(t, string(fileContents["2018-01-15-test-example-com-FAKEFINGERPRINT.public.txt"]), examplePublicKey)
		assertEqual(t, string(fileContents["2018-01-15-test-example-com-FAKEFINGERPRINT.private.encrypted.txt"]), examplePrivateKey)
		assertEqual(t, string(fileContents["2018-01-15-test-example-com-FAKEFINGERPRINT.revoke.txt"]), exampleRevocationCert)
	})

	t.Run("getZipFilename returns correct location", func(t *testing.T) {
		assertEqual(t, "/tmp/fluidkeys/backups/2018-01-15-test-example-com-FAKEFINGERPRINT.zip", getZipFilename("/tmp/fluidkeys", exampleSlug))
		assertEqual(t, "/tmp/.foo/backups/2018-01-15-test-example-com-FAKEFINGERPRINT.zip", getZipFilename("/tmp/.foo", exampleSlug))
	})

}

func assertStringSlicesEqual(t *testing.T, want []string, got []string) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("not equal: want: `%v`, got `%v`", want, got)
	}

	for i := range want {

		if want[i] != got[i] {
			t.Fatalf("not equal, want[%d]=`%v`, got[%d]=`%v`",
				i, want[i], i, got[i])
		}
	}
}

func assertEqual(t *testing.T, want string, got string) {
	if want != got {
		t.Fatalf("want = '%v', got = '%v'", want, got)
	}
}

const exampleSlug string = "2018-01-15-test-example-com-FAKEFINGERPRINT"
const examplePublicKey string = "PUBLIC"
const examplePrivateKey string = "PRIVATE"
const exampleRevocationCert string = "REVOKE"
