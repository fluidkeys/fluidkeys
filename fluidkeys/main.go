package main

import (
	"bufio"
	"fmt"
	"github.com/fluidkeys/fluidkeys/pgp_key"
	"log"
	"os"
	"os/exec"
	"regexp"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("To start using Fluidkeys, first you'll need to create a key.\nYour email address (this will help other people find your key):")
	email, _ := reader.ReadString('\n')

	fmt.Println("Generating key for", email)

	pgp_key.Generate(email)
	fmt.Println()
}

func gpg_version() {
	out, err := exec.Command("gpg", "--version").Output()
	if err != nil {
		log.Printf("Command finished with error: %v", err)
		os.Exit(1)
	}
	outString := string(out)

	re := regexp.MustCompile(`gpg \(GnuPG.*\) (\d+\.\d+\.\d+)`)

	match := re.FindStringSubmatch(outString)
	if match != nil {
		log.Printf("Hello GnuPG version %s", match[1])
		os.Exit(0)
	} else {
		log.Printf("version string not found")
		os.Exit(2)
	}
}
