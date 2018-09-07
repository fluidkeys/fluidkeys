package humanize

import (
	"fmt"
	"strconv"
)

func PluralWord(quantity int, singular, plural string) string {
	if quantity == 1 {
		return singular
	}
	return plural
}

func Plural(quantity int, singular, plural string) string {
	return fmt.Sprintf("%s %s", strconv.Itoa(quantity), PluralWord(quantity, singular, plural))
}
