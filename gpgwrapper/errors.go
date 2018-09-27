package gpgwrapper

type BadPasswordError struct {
}

func (e *BadPasswordError) Error() string { return "bad password" }
