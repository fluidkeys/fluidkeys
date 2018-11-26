package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

type Team struct {
	ID           string         `json:"id,omitempty"`
	Name         string         `json:"teamName,omitempty"`
	UUID         string         `json:"uuid,omitempty"`
	Members      []*Member      `json:"members,omitempty"`
	JoinRequests []*JoinRequest `json:"joinRequests,omitempty"`
}

type JoinRequest struct {
	PublicKey string `json:"publicKey,omitempty"`
}

type Member struct {
	PublicKey string `json:"publicKey,omitempty"`
	IsAdmin   bool   `json:"isAdmin,omitempty"`
}

func teamShow(teamUUID string) exitCode {
	out.Print("\n")

	if !isValidUUID(teamUUID) {
		printFailed("Invalid team code: " + teamUUID + "\n")
		return 1
	}

	team, err := getTeamSummary(teamUUID)
	if err != nil {
		out.Print("Error: " + err.Error() + "\n\n")
		return 1
	}

	out.Print(team.Name + "\n\n")

	out.Print("Members:\n")

	for _, member := range team.Members {
		key, err := pgpkey.LoadFromArmoredPublicKey(member.PublicKey)
		if err != nil {
			out.Print("Error: " + err.Error() + "\n\n")
			return 1
		}
		email, err := key.Email()
		if err != nil {
			out.Print("Error: " + err.Error() + "\n\n")
			return 1
		}
		line := email
		if member.IsAdmin {
			line = line + "  (Admin)"
		}
		printInfo(line)
	}
	out.Print("\n")

	requestEmails := []string{}
	out.Print("Requests to join:\n")
	for _, requests := range team.JoinRequests {
		key, err := pgpkey.LoadFromArmoredPublicKey(requests.PublicKey)
		if err != nil {
			out.Print("Error: " + err.Error() + "\n\n")
			return 1
		}
		email, err := key.Email()
		if err != nil {
			out.Print("Error: " + err.Error() + "\n\n")
			return 1
		}
		printInfo(email + " | " + key.Fingerprint().String())
		requestEmails = append(requestEmails, email)
	}
	out.Print("\n")

	out.Print("To approve these requests run:\n")
	cmd := "fk team approve " + teamUUID + " " + strings.Join(requestEmails, " ")
	out.Print("    " + colour.CommandLineCode(cmd) + "\n\n")

	return 0
}

func getTeamSummary(teamUUID string) (*Team, error) {
	url := getTeamServerURL("/teams/" + teamUUID)

	teamserviceClient := http.Client{
		Timeout: time.Second * 2, // Maximum of 2 secs
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "fk-client")

	res, err := teamserviceClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	team := Team{}
	err = json.Unmarshal(body, &team)
	if err != nil {
		return nil, err
	}

	return &team, nil
}
