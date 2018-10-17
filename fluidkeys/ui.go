package main

import (
	"fmt"
	"github.com/fluidkeys/fluidkeys/colour"
)

func printInfo(message string) {
	fmt.Print(" " + colour.Info("▸") + "   " + message + "\n")
}
