package main

import (
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
)

func printInfo(message string) {
	out.Print(" " + colour.Info("▸") + "   " + message + "\n")
}
