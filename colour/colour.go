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

import (
	"strings"
)

func Custom(fgColor string, bgColor string, message string) string {

	var fgColorCode string
	var bgColorCode string

	fgColor = strings.ToLower(fgColor)
	bgColor = strings.ToLower(bgColor)

	switch fgColor {
	case "red":
		fgColorCode = fgRed
	case "black":
		fgColorCode = fgBlack
	case "blue":
		fgColorCode = fgBlue
	case "cyan":
		fgColorCode = fgCyan
	case "magenta":
		fgColorCode = fgMagenta
	case "green":
		fgColorCode = fgGreen
	case "white":
		fgColorCode = fgWhite
	case "yellow":
		fgColorCode = fgYellow
	default:
		fgColorCode = fgWhite
	}

	switch bgColor {
	case "red":
		bgColorCode = bgRed
	case "black":
		bgColorCode = bgBlack
	case "blue":
		bgColorCode = bgBlue
	case "cyan":
		bgColorCode = bgCyan
	case "magenta":
		bgColorCode = bgMagenta
	case "green":
		bgColorCode = bgGreen
	case "white":
		bgColorCode = bgWhite
	case "yellow":
		bgColorCode = bgYellow
	default:
		bgColorCode = bgBlack
	}

	return bgColorCode + fgColorCode + message + reset
}

func Success(message string) string {
	return green(message)
}

func Failure(message string) string {
	return red(message)
}

func Info(message string) string {
	return bright + blue(message)
}

func Warning(message string) string {
	return yellow(message)
}

func Danger(message string) string {
	return red(message)
}

func Error(message string) string {
	return red(message)
}

func ErrorDetail(message string) string {
	return dim + message + reset
}

func TableHeader(message string) string {
	return bright + blue(message)
}

func Cmd(message string) string {
	return bright + blue(message)
}

func Disabled(message string) string {
	return grey(message)
}

func Greeting(message string) string {
	return bright + magenta(message)
}

func Header(message string) string {
	return bgLightBlue + fgBlack + message + reset
}

func Waiting(message string) string {
	return fgCyan + message + reset
}

func File(filename string) string {
	return yellow(filename)
}

func underline(message string) string {
	return underscore + message + reset
}

func bold(message string) string {
	return bright + message + reset
}

func green(message string) string {
	return fgGreen + message + reset
}

func blue(message string) string {
	return fgBlue + message + reset
}

func magenta(message string) string {
	return fgMagenta + message + reset
}

func red(message string) string {
	return fgRed + message + reset
}

func black(message string) string {
	return bgWhite + fgBlack + message + reset
}

func cyan(message string) string {
	return fgCyan + message + reset
}

func white(message string) string {
	return bgBlack + fgWhite + message + reset
}

func yellow(message string) string {
	return fgYellow + message + reset
}

func grey(message string) string {
	return bright + fgBlack + message + reset
}

// StripAllColourCodes strips all the ANSI colour codes from a string
func StripAllColourCodes(message string) string {
	for _, colourCode := range allColourCodes {
		message = strings.Replace(message, colourCode, "", -1)
	}

	return message
}
