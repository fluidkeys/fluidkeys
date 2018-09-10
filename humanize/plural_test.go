package humanize

import "fmt"

func ExamplePluralize() {
	fmt.Println(Pluralize(2, "fox", "foxes"))
	// Output: 2 foxes
}
