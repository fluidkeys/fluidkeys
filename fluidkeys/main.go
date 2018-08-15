package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/pgp_key"
	"github.com/fluidkeys/go-diceware/diceware"
)

const DicewareNumberOfWords int = 6
const DicewareSeparator string = "."

type DicewarePassword struct {
	words     []string
	separator string
}

func (d DicewarePassword) AsString() string {
	return strings.Join(d.words, d.separator)
}

func main() {
	email := promptForEmail()
	password := generatePassword(DicewareNumberOfWords, DicewareSeparator)
	displayPassword(password)

	fmt.Println("Generating key for", email)

	pgp_key.Generate(email)
	fmt.Println()
}

func promptForInputWithPipes(prompt string, reader *bufio.Reader) string {
	fmt.Printf("\n" + prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	return strings.TrimRight(response, "\n")
}

func promptForInput(prompt string) string {
	return promptForInputWithPipes(prompt, bufio.NewReader(os.Stdin))
}

func promptForEmail() string {
	fmt.Print("To start using Fluidkeys, first you'll need to create a key.\nYour email address (this will help other people find your key)\n")
	return promptForInput("[email] : ")
}

func generatePassword(numberOfWords int, separator string) DicewarePassword {
	return DicewarePassword{
		words:     diceware.MustGenerate(numberOfWords),
		separator: separator,
	}
}

func displayPassword(password DicewarePassword) {
	fmt.Printf("Here's a password, you should now write this down on a piece of paper and keep it with you on your person:\n")

	fmt.Printf("\n  %v\n", colour.LightBlue(password.AsString()))

	promptForInput("Press enter when you've written it down. ")
}
