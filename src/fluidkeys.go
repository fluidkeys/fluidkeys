package main

import (
	"log"
	"os"
	"os/exec"
	"regexp"
)

func main() {
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
