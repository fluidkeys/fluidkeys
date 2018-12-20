// MIT License
//
// Copyright (c) 2018 Amulya Kashyap
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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

	bgBlack     = "\x1b[40m"
	bgRed       = "\x1b[41m"
	bgGreen     = "\x1b[42m"
	bgYellow    = "\x1b[43m"
	bgBlue      = "\x1b[44m"
	bgMagenta   = "\x1b[45m"
	bgCyan      = "\x1b[46m"
	bgWhite     = "\x1b[47m"
	bgLightBlue = "\x1b[104m"
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
	bgLightBlue,
}
