package config

import (
	"io"
	"io/ioutil"
	"os"
)

type fileFunctionsInterface interface {
	OsStat(string) (os.FileInfo, error)                      // like os.Stat
	OsOpen(string) (io.Reader, error)                        // like os.Open
	IoutilWriteFile(string, []byte, os.FileMode) (int error) // like ioutil.WriteFile
}

// fileFunctionsPassthrough simply passes calls through to the real os/io/ioutil
// function
type fileFunctionsPassthrough struct {
}

func (p *fileFunctionsPassthrough) OsStat(filename string) (os.FileInfo, error) {
	return os.Stat(filename)
}

func (p *fileFunctionsPassthrough) OsOpen(filename string) (io.Reader, error) {
	return os.Open(filename)
}

func (p *fileFunctionsPassthrough) IoutilWriteFile(filename string, data []byte, mode os.FileMode) (int error) {
	return ioutil.WriteFile(filename, data, mode)
}
