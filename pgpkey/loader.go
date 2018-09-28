package pgpkey

type Loader struct {
}

func (f *Loader) LoadFromArmoredEncryptedPrivateKey(armoredKey string, password string) (*PgpKey, error) {
	return LoadFromArmoredEncryptedPrivateKey(armoredKey, password)
}
