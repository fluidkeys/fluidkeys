package main

type IncorrectPassword struct {
	message       string
	originalError string
}

func (e *IncorrectPassword) Error() string {
	if e.message != "" {
		return e.message
	} else {
		return "the password was incorrect"
	}
}
