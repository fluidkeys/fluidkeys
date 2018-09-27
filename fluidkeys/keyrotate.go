package main

import (
	"fmt"
	"github.com/fluidkeys/fluidkeys/colour"
)


func printCheckboxPending(actionText string) {
	fmt.Printf("    [.] %s\r", actionText)
}

func printCheckboxSuccess(actionText string) {
	fmt.Printf("    [%s] %s\n", colour.Success("✔"), actionText)
}

func printCheckboxSkipped(actionText string) {
	fmt.Printf("    [%s] %s\n", colour.Info("-"), actionText)
}

func printCheckboxFailure(actionText string, err error) {
	fmt.Printf("\r    %s %s\n", colour.Error("[!]"), actionText)
	fmt.Printf("\r        %s\n", colour.Error(fmt.Sprintf("%s", err)))
}

