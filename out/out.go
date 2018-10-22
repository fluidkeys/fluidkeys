package out

import "fmt"

var Outputter OutputterInterface

func Print(message string) {
	Outputter.Print(message)
}

func PrintTheBuffer() {
	Outputter.PrintTheBuffer()
}

type OutputterInterface interface {
	Print(message string)
	PrintTheBuffer()
}

type TerminalOutputter struct{}

func (o *TerminalOutputter) Print(message string) {
	fmt.Print(message)
}

func (o *TerminalOutputter) PrintTheBuffer() {}

type CronOutputter struct {
	buffer string
}

func (o *CronOutputter) Print(message string) {
	o.buffer += message
}

func (o *CronOutputter) PrintTheBuffer() {
	fmt.Print(o.buffer)
}
