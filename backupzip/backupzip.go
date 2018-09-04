package backupzip

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Writes a ZIP file containing text files with ASCII-armored backups of the
// given public and private key.
//
// Returns: the full filename of the ZIP file that was written
func OutputZipBackupFile(fluidkeysDir, uniqueSlug string, armoredPublicKey string, armoredPrivateKey string, armoredRevocationCert string) (filename string, err error) {
	filename = getZipFilename(fluidkeysDir, uniqueSlug)

	backupZipFile, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("os.Create(%s) failed: %v", filename, err)
	}
	defer backupZipFile.Close()

	err = WriteZipData(backupZipFile, uniqueSlug, armoredPublicKey, armoredPrivateKey, armoredRevocationCert)
	if err != nil {
		return "", fmt.Errorf("WriteZipData failed: %v", err)
	}
	return filename, nil
}

// Write ZIP data to the given `w` io.Writer
func WriteZipData(w io.Writer, uniqueSlug string, armoredPublicKey string, armoredPrivateKey string, armoredRevocationCert string) (err error) {
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	err = writeDataToFileInZip(zipWriter, []byte(armoredPublicKey), uniqueSlug+".public.txt")
	if err != nil {
		return err
	}

	err = writeDataToFileInZip(zipWriter, []byte(armoredPrivateKey), uniqueSlug+".private.encrypted.txt")
	if err != nil {
		return
	}

	err = writeDataToFileInZip(zipWriter, []byte(armoredRevocationCert), uniqueSlug+".revoke.txt")
	if err != nil {
		return
	}
	return
}

func writeDataToFileInZip(zipWriter *zip.Writer, data []byte, filename string) error {
	writer, err := makeFileWriter(zipWriter, filename)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)

	if err != nil {
		return fmt.Errorf("failed to write data to `%s` in ZIP: %v", filename, err)
	}
	return nil
}

func makeFileWriter(zipWriter *zip.Writer, filename string) (io.Writer, error) {
	header := zip.FileHeader{
		Name:     filename,
		Method:   zip.Deflate,
		Modified: time.Now(),
	}

	writer, err := zipWriter.CreateHeader(&header)
	if err != nil {
		return nil, fmt.Errorf("zipWriter.CreateHeader(..) failed: %v", err)
	}
	return writer, nil
}

func getZipFilename(fluidkeysDir string, slug string) string {
	backupDirectory := filepath.Join(fluidkeysDir, "backups")
	os.MkdirAll(backupDirectory, 0700)
	return filepath.Join(backupDirectory, slug+".zip")
}
