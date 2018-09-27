package main

import (
	"fmt"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

// getDecryptedPrivateKeyAndPassword prompts the user for a password, tests it
// and if successful, returns a decrypted private key and the password they
// provided.
// If the password is incorrect, it loops until they get it right.
func getDecryptedPrivateKeyAndPassword(publicKey *pgpkey.PgpKey) (*pgpkey.PgpKey, string, error) {
	for {
		password := getPassword(publicKey)
		privateKey, err := loadPrivateKey(publicKey.Fingerprint(), password, &gpg, &pgpkey.Loader{})

		if err != nil {
			if _, ok := err.(*decryptError); ok {
				fmt.Printf("Password appeared to be incorrect.\n")
				continue
			} else {
				// different type of error
				return nil, "", fmt.Errorf("error loading private key: %v", err)
			}
		}

		return privateKey, password, nil
	}
}

// getPassword asks the user for a password and returns the result
func getPassword(key *pgpkey.PgpKey) string {
	return promptForInput(fmt.Sprintf("Enter password for %s:\n -> ", displayName(key)))
}
