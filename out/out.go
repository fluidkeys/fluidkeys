package out

import "fmt"

var outputter outputterInterface

func init() {
	SetOutputToTerminal()
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
