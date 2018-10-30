package out

import (
	"fmt"
	"github.com/fluidkeys/fluidkeys/colour"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var outputter outputterInterface
// NoLogCharacter can be added to an output message to prevent that line from
// being saved to the log file.
const NoLogCharacter string = "🤫"

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

	if lines := splitIntoLogLines(message); len(lines) > 0 {
		for _, line := range lines {
			log.Print(line)
		}
	}
}

func PrintTheBuffer() {
	if theBufferOutputter, ok := outputter.(*bufferOutputter); ok {
		theBufferOutputter.printTheBuffer()
	}
}

// splitIntoLogLines takes an output message (with newlines) and returns a
// slice of lines for suitable for outputting with log.Print, namely:
// * remove colour codes
// * remove blank lines
// * redact lines containing NoLogCharacter
func splitIntoLogLines(message string) []string {
	message = colour.StripAllColourCodes(message)

	outLines := []string{}
	for _, line := range strings.Split(message, "\n") {
		if strings.Trim(line, "\n") == "" {
			continue
		} else if strings.Contains(line, NoLogCharacter) {
			line = "*** line redacted from log file ***"
		}
		outLines = append(outLines, line)
	}
	return outLines
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
