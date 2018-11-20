package main

import (
	"regexp"

	"github.com/fluidkeys/fluidkeys/out"
)

func teamJoin(teamUuid string) exitCode {
	out.Print("\n")

	if !isValidUUID(teamUuid) {
		printFailed("Invalid invite code: " + teamUuid + "\n")
		return 1
	}

	out.Print("Valid uuid: " + teamUuid + "\n")
	return 0
}

func isValidUUID(uuid string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	return r.MatchString(uuid)
}
