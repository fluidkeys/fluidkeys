package main

import (
	"bufio"
	"io"
	"os"

	"github.com/fluidkeys/fluidkeys/api"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func secretSend(recipientEmail string) exitCode {
	out.Print("\n")
	out.Print("[type or paste your message, ending by typing Ctrl-D]\n\n")

	secret, err := scanUntilEOF()
	if err != nil {
		panic(err)
		return 1
	}

	client := api.NewClient()
	armoredPublicKey, _, err := client.GetPublicKey(recipientEmail)
	if err != nil {
		out.Print("Error encountered trying to get public key for " + recipientEmail)
	}

	pgpKey, err := pgpkey.LoadFromArmoredPublicKey(armoredPublicKey)
	if err != nil {
		out.Print(err.Error())
		return 1
	}

	//TODO: Encrypt the secret and POST back to API
	return 0
}

func scanUntilEOF() (message string, err error) {
	reader := bufio.NewReader(os.Stdin)
	var output []rune

	for {
		input, _, err := reader.ReadRune()
		if err != nil && err == io.EOF {
			break
		}
		output = append(output, input)
	}

	return string(output), nil
}
