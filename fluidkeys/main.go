package main

import (
	"bufio"
	"fmt"
	"github.com/fluidkeys/fluidkeys/pgp_key"
	"os"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("To start using Fluidkeys, first you'll need to create a key.\nYour email address (this will help other people find your key):")
	email, _ := reader.ReadString('\n')

	fmt.Println("Generating key for", email)

	pgp_key.Generate(email)
	fmt.Println()
}
