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

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("To start using Fluidkeys, first you'll need to create a key.\nYour email address (this will help other people find your key):")
	email, _ := reader.ReadString('\n')

	fmt.Printf("Here's a password, you should now write this down on a piece of paper and keep it with you on your person:\n")

	password := strings.Join(diceware.MustGenerate(6), ".")

	fmt.Printf("\n  %v\n\n", colour.LightBlue(password))

	fmt.Println("Generating key for", email)

	pgp_key.Generate(email)
	fmt.Println()
}
