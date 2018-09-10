package humanize

import (
	"fmt"
	"strconv"
)

// Plural returns the quantity then either the `singular` (fox) or `plural`
// (foxes) depending on that given `quantity`
// e.g. `Plural(2, "fox", "foxes")` returns "2 foxes"
func Pluralize(quantity int, singular, plural string) string {
	str := fmt.Sprintf("%s ", strconv.Itoa(quantity))
	if quantity == 1 {
		str += singular
	} else {
		str += plural
	}
	return str
}
