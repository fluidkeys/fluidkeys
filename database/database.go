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

package database

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
)

type Database struct {
	jsonFilename string
}

type Message struct {
	KeysImportedIntoGnuPG []KeyImportedIntoGnuPGMessage
}

type KeyImportedIntoGnuPGMessage struct {
	Fingerprint fpr.Fingerprint
}

func New(fluidkeysDirectory string) Database {
	jsonFilename := filepath.Join(fluidkeysDirectory, "db.json")
	return Database{jsonFilename: jsonFilename}
}

func (db *Database) RecordFingerprintImportedIntoGnuPG(newFingerprint fpr.Fingerprint) error {
	existingFingerprints, err := db.GetFingerprintsImportedIntoGnuPG()
	if err != nil {
		return err
	}

	allFingerprints := append(existingFingerprints, newFingerprint)
	message := makeMessageFromFingerprints(deduplicate(allFingerprints))

	file, err := os.Create(db.jsonFilename)
	if err != nil {
		return fmt.Errorf("Couldn't open '%s': %v", db.jsonFilename, err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")

	return encoder.Encode(message)
}

func makeMessageFromFingerprints(fingerprints []fpr.Fingerprint) Message {
	var messages []KeyImportedIntoGnuPGMessage

	for _, fingerprint := range fingerprints {
		messages = append(messages, KeyImportedIntoGnuPGMessage{Fingerprint: fingerprint})
	}

	message := Message{
		KeysImportedIntoGnuPG: messages,
	}
	return message
}

func (db *Database) GetFingerprintsImportedIntoGnuPG() ([]fpr.Fingerprint, error) {
	file, err := os.Open(db.jsonFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return []fpr.Fingerprint{}, nil
		} else {
			return nil, fmt.Errorf("Couldn't open '%s': %v", db.jsonFilename, err)
		}
	}

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll(..) error: %v", err)
	}

	var message Message

	if err := json.Unmarshal(byteValue, &message); err != nil {
		return nil, fmt.Errorf("error loading json: %v", err)
	}

	var fingerprints []fpr.Fingerprint

	for _, v := range message.KeysImportedIntoGnuPG {
		fingerprints = append(fingerprints, v.Fingerprint)
	}

	return deduplicate(fingerprints), nil
}

func deduplicate(slice []fpr.Fingerprint) []fpr.Fingerprint {
	sliceMap := make(map[fpr.Fingerprint]bool)
	for _, v := range slice {
		sliceMap[v] = true
	}

	var deduped []fpr.Fingerprint
	for key, _ := range sliceMap {
		deduped = append(deduped, key)
	}
	return deduped
}
