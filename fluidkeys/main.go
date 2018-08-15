package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/pgpkey"
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
	channel := make(chan pgpkey.PgpKey)
	go generatePgpKey(email, channel)

	password := generatePassword(DicewareNumberOfWords, DicewareSeparator)

	displayPassword(password)
	confirmRandomWord(password)

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

func confirmRandomWord(password DicewarePassword) {
	rand.Seed(time.Now().UnixNano())
	randomIndex := rand.Intn(len(password.words))
	correctWord := password.words[randomIndex]
	wordOrdinal := humanize.Ordinal(randomIndex + 1)
	givenWord := ""

	for {
		fmt.Printf("Enter the %s word\n", wordOrdinal)
		givenWord = promptForInput("[" + wordOrdinal + " word] : ")
		if givenWord == correctWord {
			fmt.Printf("Correct!\n")
			break
		}
	}
}
