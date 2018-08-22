package backupzip

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Writes a ZIP file containing text files with ASCII-armored backups of the
// given public and private key.
//
// Returns: the full filename of the ZIP file that was written
func OutputZipBackupFile(fluidkeysDir, armoredPublicKey string, armoredPrivateKey string) (filename string, err error) {
	filename = getZipFilename(fluidkeysDir)

	backupZipFile, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("os.Create(%s) failed: %v", filename, err)
	}
	defer backupZipFile.Close()

	err = WriteZipData(backupZipFile, armoredPublicKey, armoredPrivateKey)
	if err != nil {
		return "", fmt.Errorf("WriteZipData failed: %v", err)
	}
	return filename, nil
}

// Write ZIP data to the given `w` io.Writer
func WriteZipData(w io.Writer, armoredPublicKey string, armoredPrivateKey string) (err error) {
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	err = writeDataToFileInZip(zipWriter, []byte(armoredPublicKey), "public.txt")
	if err != nil {
		return err
	}

	err = writeDataToFileInZip(zipWriter, []byte(armoredPrivateKey), "private.encrypted.txt")
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
		Name:   filename,
		Method: zip.Deflate,
	}

	writer, err := zipWriter.CreateHeader(&header)
	if err != nil {
		return nil, fmt.Errorf("zipWriter.CreateHeader(..) failed: %v", err)
	}
	return writer, nil
}

func getZipFilename(fluidkeysDir string) string {
	return filepath.Join(fluidkeysDir, "backup.zip")
}
