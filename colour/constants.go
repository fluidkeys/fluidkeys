// Copyright 2018 Paul Furley and Ian Drysdale
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

package colour

const (
	reset      = "\x1b[0m"
	bright     = "\x1b[1m"
	dim        = "\x1b[2m"
	underscore = "\x1b[4m"
	blink      = "\x1b[5m"
	reverse    = "\x1b[7m"
	hidden     = "\x1b[8m"

	fgBlack   = "\x1b[30m"
	fgRed     = "\x1b[31m"
	fgGreen   = "\x1b[32m"
	fgYellow  = "\x1b[33m"
	fgBlue    = "\x1b[34m"
	fgMagenta = "\x1b[35m"
	fgCyan    = "\x1b[36m"
	fgWhite   = "\x1b[37m"

	bgBlack   = "\x1b[40m"
	bgRed     = "\x1b[41m"
	bgGreen   = "\x1b[42m"
	bgYellow  = "\x1b[43m"
	bgBlue    = "\x1b[44m"
	bgMagenta = "\x1b[45m"
	bgCyan    = "\x1b[46m"
	bgWhite   = "\x1b[47m"
)

var allColourCodes = []string{
	reset,
	bright,
	dim,
	underscore,
	blink,
	reverse,
	hidden,

	fgBlack,
	fgRed,
	fgGreen,
	fgYellow,
	fgBlue,
	fgMagenta,
	fgCyan,
	fgWhite,

	bgBlack,
	bgRed,
	bgGreen,
	bgYellow,
	bgBlue,
	bgMagenta,
	bgCyan,
	bgWhite,
}
