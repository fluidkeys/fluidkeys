// Copyright 2018 Paul Furley and Ian Drysdale
//
// This file is part of Fluidkeys Client which makes it simple to use OpenPGP.
//
// Fluidkeys Client is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Fluidkeys Client is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Fluidkeys Client.  If not, see <https://www.gnu.org/licenses/>.

package backupzip

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/fluidkeys/fluidkeys/archiver"
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
		log.Panicf("Failed to output public key: %v", err)
	}

	privateKey, err := pgpKey.ArmorPrivate(password)
	if err != nil {
		log.Panicf("Failed to output private key: %v", err)
	}

	revocationCert, err := pgpKey.ArmorRevocationCertificate(time.Now())
	if err != nil {
		log.Panicf("Failed to output revocation cert: %v", err)
	}

	keySlug, err := pgpKey.Slug()
	if err != nil {
		log.Panicf("error getting key slug: %v", err)
	}

	filename = archiver.MakeFilePath(keySlug, "zip", fluidkeysDir, time.Now())

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
