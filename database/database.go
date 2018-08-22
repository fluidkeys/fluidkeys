package database

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type Database struct {
	jsonFilename string
}

type DatabaseMessage struct {
	KeysImportedIntoGnuPG []KeyImportedIntoGnuPGMessage
}

type KeyImportedIntoGnuPGMessage struct {
	Fingerprint string
}

func New(fluidkeysDirectory string) Database {
	jsonFilename := filepath.Join(fluidkeysDirectory, "db.json")
	return Database{jsonFilename: jsonFilename}
}

func (db *Database) RecordFingerprintImportedIntoGnuPG(newFingerprint string) error {
	existingFingerprints, err := db.GetFingerprintsImportedIntoGnuPG()
	if err != nil {
		return err
	}

	allFingerprints := append(existingFingerprints, newFingerprint)
	databaseMessage := makeDatabaseMessageFromFingerprints(allFingerprints)

	file, err := os.Create(db.jsonFilename)
	if err != nil {
		return fmt.Errorf("Couldn't open '%s': %v", db.jsonFilename, err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")

	return encoder.Encode(databaseMessage)
}

func makeDatabaseMessageFromFingerprints(fingerprints []string) DatabaseMessage {
	var messages []KeyImportedIntoGnuPGMessage

	for _, fingerprint := range fingerprints {
		messages = append(messages, KeyImportedIntoGnuPGMessage{Fingerprint: fingerprint})
	}

	databaseMessage := DatabaseMessage{
		KeysImportedIntoGnuPG: messages,
	}
	return databaseMessage
}

func (db *Database) GetFingerprintsImportedIntoGnuPG() ([]string, error) {
	file, err := os.Open(db.jsonFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		} else {
			return nil, fmt.Errorf("Couldn't open '%s': %v", db.jsonFilename, err)
		}
	}

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll(..) error: %v", err)
	}

	var databaseMessage DatabaseMessage

	json.Unmarshal(byteValue, &databaseMessage)

	var fingerprints []string

	for _, v := range databaseMessage.KeysImportedIntoGnuPG {
		fingerprints = append(fingerprints, v.Fingerprint)
	}

	return deduplicate(fingerprints), nil
}

func deduplicate(slice []string) []string {
	sliceMap := make(map[string]bool)
	for _, v := range slice {
		sliceMap[v] = true
	}

	var deduped []string
	for key, _ := range sliceMap {
		deduped = append(deduped, key)
	}
	return deduped
}
