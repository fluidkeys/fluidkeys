package database

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
)

type Database struct {
	jsonFilename string
}

type DatabaseMessage struct {
	KeysImportedIntoGnuPG []KeyImportedIntoGnuPGMessage
}

type KeyImportedIntoGnuPGMessage struct {
	KeyId string
}

func New(fluidkeysDirectory string) Database {
	jsonFilename := filepath.Join(fluidkeysDirectory, "db.json")
	return Database{jsonFilename: jsonFilename}
}

func (db *Database) RecordKeyIdImportedIntoGnuPG(newKeyId uint64) error {
	existingKeyIds, err := db.GetKeyIdsImportedIntoGnuPG()
	if err != nil {
		return err
	}

	allKeyIds := append(existingKeyIds, newKeyId)
	databaseMessage := makeDatabaseMessageFromKeyIds(allKeyIds)

	file, err := os.Create(db.jsonFilename)
	if err != nil {
		return fmt.Errorf("Couldn't open '%s': %v", db.jsonFilename, err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")

	return encoder.Encode(databaseMessage)
}

func makeDatabaseMessageFromKeyIds(keyIds []uint64) DatabaseMessage {
	var messages []KeyImportedIntoGnuPGMessage

	for _, keyId := range keyIds {
		messages = append(messages, KeyImportedIntoGnuPGMessage{KeyId: strconv.FormatUint(keyId, 16)})
	}

	databaseMessage := DatabaseMessage{
		KeysImportedIntoGnuPG: messages,
	}
	return databaseMessage
}

func (db *Database) GetKeyIdsImportedIntoGnuPG() ([]uint64, error) {
	file, err := os.Open(db.jsonFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return []uint64{}, nil
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

	var keyIds []uint64

	for _, v := range databaseMessage.KeysImportedIntoGnuPG {
		keyId, err := strconv.ParseUint(v.KeyId, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("Failed to convert Hex to 64 bit integer keyid '%v'", v.KeyId)
		}
		keyIds = append(keyIds, keyId)
	}

	return deduplicate(keyIds), nil
}

func deduplicate(slice []uint64) []uint64 {
	sliceMap := make(map[uint64]bool)
	for _, v := range slice {
		sliceMap[v] = true
	}

	var deduped []uint64
	for key, _ := range sliceMap {
		deduped = append(deduped, key)
	}
	return deduped
}
