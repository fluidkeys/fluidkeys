package main

import (
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
)

func printInfo(message string) {
	out.Print(" " + colour.Info("▸") + "   " + message + "\n")
}

func printSuccess(message string) {
	out.Print(" " + colour.Success("▸   "+message) + "\n")
}

func printSuccessfulAction(message string) {
	out.Print("    [" + colour.Success("✔") + "] " + message + "\n")
}

func printFailedAction(message string) {
	out.Print("    [" + colour.Failure("✘") + "] " + message + "\n")
}
