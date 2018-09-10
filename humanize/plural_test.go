package humanize

import "fmt"

func ExamplePlural() {
	fmt.Println(Plural(2, "fox", "foxes"))
	// Output: 2 foxes
}
