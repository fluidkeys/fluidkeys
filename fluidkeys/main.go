package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/sethvargo/go-diceware/diceware"
)

const DicewareNumberOfWords int = 6
const DicewareSeparator string = "."

const GPGMissing string = "GPG isn't working on your system 🤒\n"
const ContinueWithoutGPG string = "You can still use FluidKeys to make a key and then later import it from your backup.\n\nAlternatively, quit now [ctrl-c], install GPG then run FluidKeys again.\n"
const PromptPressEnter string = "Press enter to continue"

const PromptEmail string = "To start using Fluidkeys, first you'll need to create a key.\n\nEnter your email address, this will help other people find your key.\n"
const PromptFirstPassword string = "This is your password.\n\n* If you use a password manager, save it there now\n* Otherwise write it on a piece of paper and keep it with you\n"
const PromptLastPassword string = "That didn't match 🤷🏽 This is your last chance!\n"
const FailedToConfirmPassword string = "That didn't match. Quitting...\n"

type DicewarePassword struct {
	words     []string
	separator string
}

func (d DicewarePassword) AsString() string {
	return strings.Join(d.words, d.separator)
}

func main() {
	if !gpgwrapper.IsWorking() {
		fmt.Printf(colour.Warn("\n" + GPGMissing + "\n"))
		fmt.Printf(ContinueWithoutGPG)
		promptForInput("Press enter to continue. ")
	}
	email := promptForEmail()
	channel := make(chan pgpkey.PgpKey)
	go generatePgpKey(email, channel)

	password := generatePassword(DicewareNumberOfWords, DicewareSeparator)

	displayPassword(PromptFirstPassword, password)
	if !userConfirmedRandomWord(password) {
		displayPassword(PromptLastPassword, password)
		if !userConfirmedRandomWord(password) {
			fmt.Printf(FailedToConfirmPassword)
			os.Exit(1)
		}
	}

	fmt.Println("Generating key for", email)
	fmt.Println()

	generatedPgpKey := <-channel
	fmt.Println(generatedPgpKey.PublicKey)
}

func generatePgpKey(email string, channel chan pgpkey.PgpKey) {
	channel <- pgpkey.Generate(email)
}

func promptForInputWithPipes(prompt string, reader *bufio.Reader) string {
	fmt.Printf("\n" + prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	fmt.Print("\n")
	return strings.TrimRight(response, "\n")
}

func promptForInput(prompt string) string {
	return promptForInputWithPipes(prompt, bufio.NewReader(os.Stdin))
}

func promptForEmail() string {
	fmt.Print(PromptEmail)
	return promptForInput("[email] : ")
}

func generatePassword(numberOfWords int, separator string) DicewarePassword {
	return DicewarePassword{
		words:     diceware.MustGenerate(numberOfWords),
		separator: separator,
	}
}

func displayPassword(message string, password DicewarePassword) {
	fmt.Printf(message)
	fmt.Printf("\n  %v\n", colour.LightBlue(password.AsString()))

	promptForInput("Press enter when you've written it down. ")
}

func userConfirmedRandomWord(password DicewarePassword) bool {
	clearScreen()
	rand.Seed(time.Now().UnixNano())
	randomIndex := rand.Intn(len(password.words))
	correctWord := password.words[randomIndex]
	wordOrdinal := humanize.Ordinal(randomIndex + 1)

	fmt.Printf("Enter the %s word from your password\n", wordOrdinal)
	givenWord := promptForInput("[" + wordOrdinal + " word] : ")
	return givenWord == correctWord
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}
