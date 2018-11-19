package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
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

	request, err := http.NewRequest(
		"POST",
		getTeamServerURL("/teams"),
		bytes.NewBuffer(teamJSON),
	)
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return outputError(teamName, err.Error())
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		response.Body.Close()
		return outputError(teamName, err.Error())
	}
	jsonResponse, err := parsePostResponse([]byte(body))
	if err != nil {
		response.Body.Close()
		return outputError(teamName, err.Error())
	}

	if jsonResponse.UUID != nil {
		printSuccess("Successfully created " + teamName + "team")
		out.Print("\n")
		out.Print("Edit and send the invite below to your team:\n\n")
		out.Print("---\n")
		out.Print("  Hello! Come and join our Example Inc team on Fluidkeys.\n")
		out.Print("  Download Fluidkeys from download.fluidkeys.com then run:\n")
		out.Print("  > fk team join " + *jsonResponse.UUID + "\n")
		out.Print("---\n\n")
		out.Print("You’ll need to approve new team members by running:\n\n")
		out.Print("> fk team approve\n\n")
		response.Body.Close()
		return 0
	} else if jsonResponse.Message != nil {
		printFailed("Couldn't create the " + teamName + " team!\n")
		out.Print("Received an error: " + *jsonResponse.Message + "\n")
		response.Body.Close()
		return 1
	}

	return 1
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

type PostResponse struct {
	Message *string `json:"message"`
	UUID    *string `json:"teamUuid,omitempty"`
}

func parsePostResponse(body []byte) (*PostResponse, error) {
	var postResponse = new(PostResponse)
	err := json.Unmarshal(body, &postResponse)
	return postResponse, err
}

func outputError(teamName string, err string) exitCode {
	printFailed("Couldn't create the " + teamName + " team!\n")
	out.Print("Received an error: " + err + "\n")
	return 1
}
