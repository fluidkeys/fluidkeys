package pgp_key

import (  
  "fmt"
)

type pgp_key struct {  
  email       string
}

func Generate(email string, password string) pgp_key {
  // TODO: make the key
  k := pgp_key {email}
  return k
}

func (k pgp_key) EmailAddress() {  
  fmt.Printf("Key's email address is %s", k.email)
}
