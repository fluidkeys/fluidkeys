package main

import (
	"bufio"
	"bytes"
	"io"
	"os"

	"github.com/fluidkeys/fluidkeys/colour"

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
	armoredPublicKey, err := client.GetPublicKey(recipientEmail)
	if err != nil {
		printFailed("Couldn't get the public key for " + recipientEmail + "\n")
		return 1
	}

	printSuccess("Found public key for " + recipientEmail + "\n")

	pgpKey, err := pgpkey.LoadFromArmoredPublicKey(armoredPublicKey)
	if err != nil {
		printFailed("Couldn't load the public key:")
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	encryptedSecret, err := encryptSecret(secret, pgpKey)
	if err != nil {
		printFailed("Couldn't encrypt the secret:")
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	err = client.CreateSecret(pgpKey.Fingerprint(), encryptedSecret)
	if err != nil {
		printFailed("Couldn't send the secret to " + recipientEmail)
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	printSuccess("Successfully sent secret to " + recipientEmail + "\n")

	out.Print("Tell them to get it by running\n")
	out.Print("  " + colour.CommandLineCode("fk secret receive\n\n"))
	return 0
}

func scanUntilEOF() (message string, err error) {
	reader := bufio.NewReader(os.Stdin)
	var output []rune

	for {
		input, _, err := reader.ReadRune()
		if err == io.EOF {
			break
		} else if err != nil {
			return "", err
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
