package main

import (
	"fmt"

	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func keyPublish(privateKey *pgpkey.PgpKey) error {
	armoredPublicKey, err := privateKey.Armor()
	if err != nil {
		return fmt.Errorf("Couldn't load armored key: %s\n", err)
	}
	if err = client.UpsertPublicKey(armoredPublicKey, privateKey); err != nil {
		return fmt.Errorf("Failed to upload public key: %s", err)

	}
	return nil
}
