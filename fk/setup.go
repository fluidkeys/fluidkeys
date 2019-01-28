package fk

import (
	"fmt"
	"math/rand"
	"strings"
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

	encryptedSecret, err := encryptSecret(secretSquirrelMessage(), pgpKey)
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

func secretSquirrelMessage() (message string) {
	rand.Seed(time.Now().Unix())
	codeName := fmt.Sprintf("%s %s", adjectives[rand.Intn(len(adjectives))], nouns[rand.Intn(len(nouns))])

	message = "🐿️ This is Secret Squirrel calling " + strings.Title(codeName) + "\n"
	message = message + `   Do you copy?
   Let me know by sending me a response:
   squirrel@fluidkeys.com`
	return message
}

const (
	paulAndIanGreeting = `👋  Hello and welcome to Fluidkeys!

    We're on a mission to help teams protect themselves
    with strong encryption.
    
    We'd love to hear what you make of this pre-release.
    You can reach us at hello@fluidkeys.com
    
    Paul & Ian, Fluidkeys`
)

var (
	adjectives = []string{
		"dusty", "past", "amazing", "agreeable", "faded", "solid", "true", "wistful", "dear",
		"didactic", "spiky", "interesting", "jagged", "obedient", "amused", "furry", "rapid",
		"infamous", "succinct", "ethereal", "sable", "fantastic", "perpetual", "puzzled",
		"sneaky", "familiar", "inquisitive", "fine", "halting", "useful", "salty", "bright",
		"zesty", "gleaming", "graceful", "satisfying", "magnificent",
	}
	nouns = []string{
		"brick", "guitar", "monster", "notebook", "thunderstorm", "snowflake", "vineyard",
		"bacon", "canteen", "engineer", "fly", "raven", "bicycle", "crow", "eyelash", "bowtie",
		"ankle", "glove", "champion", "rose", "tin", "shirt", "wall", "stick", "holiday", "earth",
		"eye", "road", "cake", "sink", "brass", "sun", "stage", "table", "brake", "chair", "moon",
	}
)
