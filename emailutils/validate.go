package emailutils

import "strings"

// RoughlyValidateEmail checks whether a given string contains an @, a rough
// check as to whether it's an email address or not.
func RoughlyValidateEmail(email string) bool {
	return strings.Contains(email, "@")
}
