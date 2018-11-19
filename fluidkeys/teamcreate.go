package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/fluidkeys/fluidkeys/fingerprint"

	"github.com/fluidkeys/fluidkeys/gpgwrapper"

	"github.com/fluidkeys/fluidkeys/out"
)

type teamPostData struct {
	Name      string `json:"teamName,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
}

func teamCreate(teamName string) exitCode {
	out.Print("\n")

	email := promptForEmail("What’s your " + teamName + " email address?\n")

	availableKeys, err := keysAvailableToGetFromGpg()
	if err != nil {
		output := fmt.Sprintf("Couldn't retrieve keys from GPG: %v\n", err)
		out.Print(output)
		os.Exit(1)
	}

	var fingerprint fingerprint.Fingerprint
	existingKey := secretKeyListingsForEmail(availableKeys, email)
	if existingKey != nil {
		out.Print("You should use a separate key for each team.\n\n")
		out.Print(printSecretKeyListing(1, *existingKey))
		prompter := interactiveYesNoPrompter{}
		if prompter.promptYesNo("Use this key for "+teamName+"?", "y", nil) {
			importGPGKey(existingKey.Fingerprint)
			fingerprint = existingKey.Fingerprint
		} else {
			fingerprint = createKeyForEmail(email)
		}
	} else {
		fingerprint = createKeyForEmail(email)
	}

	key, err := loadPgpKey(fingerprint)
	if err != nil {
		out.Print(fmt.Sprintf("Failed to load key from gpg: %v\n\n", err))
		return 1
	}

	armoredPublicKey, err := key.Armor()
	if err != nil {
		panic(fmt.Sprint("Failed to output public key: ", err))
	}

	teamPost := teamPostData{
		Name:      teamName,
		PublicKey: armoredPublicKey,
	}

	teamJSON, err := json.Marshal(teamPost)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %s", err)
	}

	req, err := http.NewRequest(
		"POST",
		getTeamServerURL("/teams"),
		bytes.NewBuffer(teamJSON),
	)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	body, err := ioutil.ReadAll(resp.Body)

	fmt.Println("Response: ", string(body))
	resp.Body.Close()
	return 0
}

func secretKeyListingsForEmail(availableKeys []gpgwrapper.SecretKeyListing, email string) *gpgwrapper.SecretKeyListing {
	for _, listing := range availableKeys {
		if (len(listing.Uids) == 1) && (strings.Contains(listing.Uids[0], email)) {
			return &listing
		}
	}
	return nil
}

func getTeamServerURL(path string) string {
	urlFromEnv := os.Getenv("TEAMSERVER_URL")
	if urlFromEnv != "" {
		return urlFromEnv
	} else {
		return "http://localhost:4747" + path
	}
}
