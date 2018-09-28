package pgpkey

type LoadFromArmoredEncryptedPrivateKeyInterface interface {
	LoadFromArmoredEncryptedPrivateKey(string, string) (*PgpKey, error)
}

type ArmorInterface interface {
	Armor() (string, error)
	ArmorPrivate(string) (string, error)
}
