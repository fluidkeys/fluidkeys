package main

import (
	"bufio"
	"bytes"
	"io"
	"os"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
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

	encryptedSecret, err := encryptSecret(secret, pgpKey)
	if err != nil {
		out.Print(err.Error())
		return 1
	}

	// TODO: POST the secret back to the API
	out.Print(encryptedSecret + "\n")
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

func encryptSecret(secret string, pgpKey *pgpkey.PgpKey) (string, error) {
	buffer := bytes.NewBuffer(nil)
	message, err := armor.Encode(buffer, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}

	pgpWriteCloser, err := openpgp.Encrypt(
		message,
		[]*openpgp.Entity{&pgpKey.Entity},
		nil,
		nil,
		nil,
	)
	if err != nil {
		return "", err
	}

	_, err = pgpWriteCloser.Write([]byte(secret))
	if err != nil {
		return "", err
	}

	pgpWriteCloser.Close()
	message.Close()
	return buffer.String(), nil
}
