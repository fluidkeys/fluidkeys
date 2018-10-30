package out

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var outputter outputterInterface

func init() {
	// this is necessary for tests to use out.Print (they don't init
	// through the main function)
	SetOutputToTerminal()
}

func Load(logDirectory string) error {
	if logDirectory == "" {
		return fmt.Errorf("missing log directory")
	}
	SetOutputToTerminal()

	logFilename := filepath.Join(logDirectory, "debug.log")

	if f, err := os.OpenFile(logFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err != nil {
		return fmt.Errorf("failed to open '%s' for writing: %v", logFilename, err)
	} else {
		// configure global logger to output to this file
		log.SetOutput(f)
	}
	return nil
}

func SetOutputToTerminal() {
	outputter = &terminalOutputter{}
}

func SetOutputToBuffer() {
	outputter = &bufferOutputter{}
}

func Print(message string) {
	outputter.print(message)
}

func PrintTheBuffer() {
	if theBufferOutputter, ok := outputter.(*bufferOutputter); ok {
		theBufferOutputter.printTheBuffer()
	}
}

type outputterInterface interface {
	print(message string)
}

type terminalOutputter struct{}

func (o *terminalOutputter) print(message string) {
	fmt.Print(message)
}

type bufferOutputter struct {
	buffer string
}

func (o *bufferOutputter) print(message string) {
	o.buffer += message
}

func (o *bufferOutputter) printTheBuffer() {
	fmt.Print(o.buffer)
}
