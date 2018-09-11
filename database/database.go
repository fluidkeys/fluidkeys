package database

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/fluidkeys/fluidkeys/fingerprint"
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

func (db *Database) RecordFingerprintImportedIntoGnuPG(newFingerprint fingerprint.Fingerprint) error {
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

func makeDatabaseMessageFromFingerprints(fingerprints []fingerprint.Fingerprint) DatabaseMessage {
	var messages []KeyImportedIntoGnuPGMessage

	for _, fingerprint := range fingerprints {
		messages = append(messages, KeyImportedIntoGnuPGMessage{Fingerprint: fingerprint.Hex()})
	}

	databaseMessage := DatabaseMessage{
		KeysImportedIntoGnuPG: messages,
	}
	return databaseMessage
}

func (db *Database) GetFingerprintsImportedIntoGnuPG() ([]fingerprint.Fingerprint, error) {
	file, err := os.Open(db.jsonFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return []fingerprint.Fingerprint{}, nil
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

	var fingerprints []fingerprint.Fingerprint

	for _, v := range databaseMessage.KeysImportedIntoGnuPG {
		fingerprintString := v.Fingerprint
		parsedFingerprint, err := fingerprint.Parse(fingerprintString)
		if err != nil {
			continue
		}
		fingerprints = append(fingerprints, parsedFingerprint)
	}

	return deduplicate(fingerprints), nil
}

func deduplicate(slice []fingerprint.Fingerprint) []fingerprint.Fingerprint {
	sliceMap := make(map[fingerprint.Fingerprint]bool)
	for _, v := range slice {
		sliceMap[v] = true
	}

	var deduped []fingerprint.Fingerprint
	for key, _ := range sliceMap {
		deduped = append(deduped, key)
	}
	return deduped
}
