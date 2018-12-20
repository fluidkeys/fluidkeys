package main

import (
	"time"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
)

func setup(email string) exitCode {
	out.Print("\n")

	out.Print(colour.Greeting(paulAndIanGreeting) + "\n")
	out.Print("\n")

	out.Print("Fluidkeys makes it easy to send end-to-end encrypted secrets using PGP.\n")

	exitCode, pgpKey := keyCreate(email)
	if exitCode != 0 {
		return exitCode
	}

	encryptedSecret, err := encryptSecret(colour.Warning(secretSquirrelMessage), pgpKey)
	if err != nil {
		printFailed("Couldn't encrypt a test secret message:")
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	email, err = pgpKey.Email()
	if err != nil {
		printFailed("Couldn't get email address for key:")
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	err = client.CreateSecret(pgpKey.Fingerprint(), encryptedSecret)
	if err != nil {
		printFailed("Couldn't send a test secret to " + email)
		out.Print("Error: " + err.Error() + "\n")
		return 1
	}

	time.Sleep(3 * time.Second)

	out.Print("🛎️  You've got a new secret. Read it by running:\n\n")
	out.Print(colour.CommandLineCode("fk secret receive") + "\n\n")

	return 0
}

const paulAndIanGreeting = `👋  Hello and welcome to Fluidkeys!

    We're on a mission to help teams protect themselves
    with strong encryption.
    
    We'd love to hear what you make of this pre-release.
    You can reach us at hello@fluidkeys.com
    
    Paul & Ian, Fluidkeys`

const secretSquirrelMessage = `🐿️  This is Secret Squirrel calling Dusty Snowflake.
   Do you copy?
   Let me know by sending me a response:
   squirrel@fluidkeys.com
`
