// Copyright 2019 Paul Furley and Ian Drysdale
//
// This file is part of Fluidkeys Client which makes it simple to use OpenPGP.
//
// Fluidkeys Client is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Fluidkeys Client is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Fluidkeys Client.  If not, see <https://www.gnu.org/licenses/>.

package scheduler

import (
	"io/ioutil"
	"os"
)

type fileFunctionsInterface interface {
	OsRemove(string) error                                   // like os.Remove
	OsStat(string) (os.FileInfo, error)                      // like os.Stat
	IoutilWriteFile(string, []byte, os.FileMode) (int error) // like ioutil.WriteFile
}

// fileFunctionsPassthrough simply passes calls through to the real os/io/ioutil
// function
type fileFunctionsPassthrough struct {
}

func (p *fileFunctionsPassthrough) OsRemove(filename string) error {
	return os.Remove(filename)
}

func (p *fileFunctionsPassthrough) OsStat(filename string) (os.FileInfo, error) {
	return os.Stat(filename)
}

func (p *fileFunctionsPassthrough) IoutilWriteFile(filename string, data []byte, mode os.FileMode) (int error) {
	return ioutil.WriteFile(filename, data, mode)
}
