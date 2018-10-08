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

func TableHeader(message string) string {
	return bright + blue(message)
}

func CommandLineCode(message string) string {
	return bright + blue(message)
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
