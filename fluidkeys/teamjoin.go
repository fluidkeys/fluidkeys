package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"regexp"
	"time"

	"github.com/fluidkeys/fluidkeys/out"
)

type teamJoinRequestData struct {
	PublicKey string `json:"publicKey,omitempty"`
}

func teamJoin(teamUuid string) exitCode {
	out.Print("\n")

	if !isValidUUID(teamUuid) {
		printFailed("Invalid invite code: " + teamUuid + "\n")
		return 1
	}

	teamName, err := getTeamName(teamUuid)
	if err != nil {
		out.Print("Error retrieving team name: " + err.Error() + "\n")
	}

	email := promptForEmail("What’s your " + teamName + " email address?\n")

	armoredPublicKey, err := importOrCreateKeyForEmail(email, teamName)
	if err != nil {
		out.Print(err.Error() + "\n")
		return 1
	}

	joinRequestData := teamJoinRequestData{
		PublicKey: armoredPublicKey,
	}

	joinRequestJSON, err := json.Marshal(joinRequestData)
	if err != nil {
		out.Print("Error marshalling JSON: " + err.Error() + "\n")
		return 1
	}

	request, err := http.NewRequest(
		"POST",
		getTeamServerURL("/teams/"+teamUuid+"/request"),
		bytes.NewBuffer(joinRequestJSON),
	)
	request.Header.Set("User-Agent", "fk-client")
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)

	if response.StatusCode == 201 {
		printSuccess("Successfully requested to join the team\n")
		out.Print("The team admin will need to approve your request.\n\n")
		return 0
	}

	printFailed("Failed to request to join the team")
	return 1
}

func isValidUUID(uuid string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	return r.MatchString(uuid)
}

type teamSummary struct {
	Name string `json:"teamName"`
}

func getTeamName(teamUuid string) (string, error) {
	url := getTeamServerURL("/teams/" + teamUuid + "/summary")

	teamserviceClient := http.Client{
		Timeout: time.Second * 2, // Maximum of 2 secs
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "fk-client")

	res, err := teamserviceClient.Do(req)
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	summary := teamSummary{}
	err = json.Unmarshal(body, &summary)
	if err != nil {
		return "", err
	}

	return summary.Name, nil
}
