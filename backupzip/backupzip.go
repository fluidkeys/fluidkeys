package backupzip

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fluidkeys/fluidkeys/pgpkey"
)

// Writes a ZIP file containing text files with ASCII-armored backups of the
// given public and private key. The private key is encrypted with the
// password passed to this function
//
// Returns: the full filename of the ZIP file that was written
func OutputZipBackupFile(
	fluidkeysDir string,
	pgpKey *pgpkey.PgpKey,
	password string,
) (filename string, err error) {
	publicKey, err := pgpKey.Armor()
	if err != nil {
		panic(fmt.Sprint("Failed to output public key: ", err))
	}

	privateKey, err := pgpKey.ArmorPrivate(password)
	if err != nil {
		panic(fmt.Sprint("Failed to output private key: ", err))
	}

	revocationCert, err := pgpKey.ArmorRevocationCertificate(time.Now())
	if err != nil {
		panic(fmt.Sprint("Failed to output revocation cert: ", err))
	}

	keySlug, err := pgpKey.Slug()
	if err != nil {
		panic(fmt.Sprintf("Failed to get slug for key to work out backup location"))
	}

	filename = getZipFilename(fluidkeysDir, keySlug, time.Now())

	backupZipFile, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("os.Create(%s) failed: %v", filename, err)
	}
	defer backupZipFile.Close()

	err = WriteZipData(backupZipFile, keySlug, publicKey, privateKey, revocationCert)
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

func getZipFilename(fluidkeysDir string, slug string, now time.Time) string {
	dateSubdirectory := now.Format("2006-01-02")
	backupDirectory := filepath.Join(fluidkeysDir, "backups", dateSubdirectory)
	os.MkdirAll(backupDirectory, 0700)
	return filepath.Join(backupDirectory, slug+".zip")
}
