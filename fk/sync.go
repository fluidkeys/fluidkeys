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

package fk

import (
	"github.com/docopt/docopt-go"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/ui"
)

func syncSubcommand(args docopt.Opts) exitCode {
	return sync()
}

func sync() (code exitCode) {
	out.Print("\n")
	out.Print("-> " + colour.Cmd("fk key maintain automatic") + "\n")

	if exitCode := keyMaintain(false, true); exitCode != 0 {
		code = exitCode
	}

	out.Print("\n")
	out.Print("-> " + colour.Cmd("fk team fetch") + "\n\n")
	if exitCode := teamFetch(true); exitCode != 0 {
		code = exitCode
	}

	return code
}
