// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"strconv"
	"time"

	"github.com/fluidkeys/crypto/openpgp/elgamal"
	"github.com/fluidkeys/crypto/openpgp/errors"
	"github.com/fluidkeys/crypto/openpgp/s2k"
)

// https://tools.ietf.org/html/rfc4880#section-5.5.3
const (
	S2KUsageConventionUnencrypted = 0

	S2KUsageConventionPlaintextChecksum = 255

	S2KUsageConventionEncryptedSha1 = 254
)

// PrivateKey represents a possibly encrypted private key. See RFC 4880,
// section 5.5.3.
type PrivateKey struct {
	PublicKey
	Encrypted     bool // if true then the private key is unavailable until Decrypt has been called.
	encryptedData []byte
	cipher        CipherFunction
	s2k           func(out, in []byte)
	PrivateKey    interface{} // An *{rsa|dsa|ecdsa}.PrivateKey or a crypto.Signer.
	sha1Checksum  bool
	iv            []byte
}

func NewRSAPrivateKey(currentTime time.Time, priv *rsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewRSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewDSAPrivateKey(currentTime time.Time, priv *dsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewDSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewElGamalPrivateKey(currentTime time.Time, priv *elgamal.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewElGamalPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

func NewECDSAPrivateKey(currentTime time.Time, priv *ecdsa.PrivateKey) *PrivateKey {
	pk := new(PrivateKey)
	pk.PublicKey = *NewECDSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

// NewSignerPrivateKey creates a sign-only PrivateKey from a crypto.Signer that
// implements RSA or ECDSA.
func NewSignerPrivateKey(currentTime time.Time, signer crypto.Signer) *PrivateKey {
	pk := new(PrivateKey)
	switch pubkey := signer.Public().(type) {
	case rsa.PublicKey:
		pk.PublicKey = *NewRSAPublicKey(currentTime, &pubkey)
		pk.PubKeyAlgo = PubKeyAlgoRSASignOnly
	case ecdsa.PublicKey:
		pk.PublicKey = *NewECDSAPublicKey(currentTime, &pubkey)
	default:
		panic("openpgp: unknown crypto.Signer type in NewSignerPrivateKey")
	}
	pk.PrivateKey = signer
	return pk
}

func (pk *PrivateKey) parse(r io.Reader) (err error) {
	err = (&pk.PublicKey).parse(r)
	if err != nil {
		return
	}
	var buf [1]byte
	_, err = readFull(r, buf[:])
	if err != nil {
		return
	}

	s2kType := buf[0]

	switch s2kType {
	case S2KUsageConventionUnencrypted:
		pk.s2k = nil
		pk.Encrypted = false
	case S2KUsageConventionEncryptedSha1, S2KUsageConventionPlaintextChecksum:
		_, err = readFull(r, buf[:])
		if err != nil {
			return
		}
		pk.cipher = CipherFunction(buf[0])
		pk.Encrypted = true
		pk.s2k, err = s2k.Parse(r)
		if err != nil {
			return
		}
		if s2kType == S2KUsageConventionEncryptedSha1 {
			pk.sha1Checksum = true
		}
	default:
		return errors.UnsupportedError(fmt.Sprintf("deprecated s2k function in private key, s2kType: %v", s2kType))
	}

	if pk.Encrypted {
		blockSize := pk.cipher.blockSize()
		if blockSize == 0 {
			return errors.UnsupportedError("unsupported cipher in private key: " + strconv.Itoa(int(pk.cipher)))
		}
		pk.iv = make([]byte, blockSize)
		_, err = readFull(r, pk.iv)
		if err != nil {
			return
		}
	}

	pk.encryptedData, err = ioutil.ReadAll(r)
	if err != nil {
		return
	}

	if !pk.Encrypted {
		return pk.parsePrivateKey(pk.encryptedData)
	}

	return
}

func mod64kHash(d []byte) uint16 {
	var h uint16
	for _, b := range d {
		h += uint16(b)
	}
	return h
}

func (pk *PrivateKey) Serialize(w io.Writer, config *Config) (err error) {
	if config.SerializePrivatePassword == "" {
		return pk.SerializeUnencrypted(w)
	} else {
		buf := bytes.NewBuffer(nil)
		err := pk.SerializeEncrypted(buf, config)
		w.Write(buf.Bytes())
		return err
	}
}

func (pk *PrivateKey) SerializeUnencrypted(w io.Writer) (err error) {

	publicKeyBytes, err := getPublicKeyBytes(pk)

	if err != nil {
		return
	}

	privateKeyHeaderBytes, err := getPrivateKeyHeaderBytes(pk)

	privateKeyBytes, err := getPrivateKeyBytes(pk)
	if err != nil {
		return
	}

	checksumBytes := getChecksumBytes(privateKeyBytes)

	ptype := getPrivateKeyPacketType(pk)

	err = serializeHeader(w, ptype, len(publicKeyBytes)+len(privateKeyHeaderBytes)+len(privateKeyBytes)+len(checksumBytes))
	if err != nil {
		return
	}
	_, err = w.Write(publicKeyBytes)
	if err != nil {
		return
	}

	_, err = w.Write(privateKeyHeaderBytes)
	if err != nil {
		return
	}

	_, err = w.Write(privateKeyBytes)
	if err != nil {
		return
	}

	_, err = w.Write(checksumBytes[:])
	if err != nil {
		return
	}

	return
}

/* it should ultimately look like this (from `pgpdump`)

   packet   /   New: Secret Key Packet(tag 5)(1862 bytes)
   header   \   Ver 4 - new

            /   Public key creation time - Thu Feb 23 11:57:49 GMT 2017
   public   |   Pub alg - RSA Encrypt or Sign(pub 1)
      key   |   RSA n(4096 bits) - ...
            \   RSA e(17 bits) - ...


            /   Sym alg - AES with 128-bit key(sym 7)
encryption  |   Iterated and salted string-to-key(s2k 3):
    header  |   	Hash alg - SHA1(hash 2)
   (algo +  |   	Salt - 5a d7 95 6d 28 ac af 2c
    S2K)    \   	Count - 62914560(coded count 254)

            /   IV - da c5 6d dc 34 c6 2d f7 dc 68 e0 b4 19 a3 62 49
            |   Encrypted RSA d
 crypto     |   Encrypted RSA p
  data      |   Encrypted RSA q
            |   Encrypted RSA u
            \   Encrypted SHA1 hash

*/

func (pk *PrivateKey) SerializeEncrypted(w io.Writer, config *Config) (err error) {
	cipher := CipherAES128 // TODO: don't hardcode, get from Config?
	password := config.SerializePrivatePassword

	if password == "" {
		return errors.InvalidArgumentError("SerializeEncrypted called with empty config.SerializePrivatePassword")
	}

	publicKeyBytes, err := getPublicKeyBytes(pk)
	if err != nil {
		return
	}

	plaintextPrivateKeyBytes, err := getPrivateKeyBytes(pk)
	if err != nil {
		return
	}

	plaintextSha1 := makeSha1Hash(plaintextPrivateKeyBytes)

	encryptionHeaderBytes, symmetricKey, err := getS2KHeaderAndSymmetricKey(
		[]byte(password),
		cipher,
	)
	if err != nil {
		return
	}

	// TODO: use config.Random()
	initialVectorBytes, err := getRandomBytes(cipher.blockSize(), rand.Reader)
	if err != nil {
		return
	}

	plaintextBuf := bytes.NewBuffer(nil)
	plaintextBuf.Write(plaintextPrivateKeyBytes)
	plaintextBuf.Write(plaintextSha1)
	plaintext := plaintextBuf.Bytes()

	encryptedPrivateKeyAndSha1Bytes, err := symmetricEncrypt(
		plaintext,
		cipher,
		symmetricKey,
		initialVectorBytes,
	)

	if err != nil {
		return
	}

	ptype := getPrivateKeyPacketType(pk)

	s2kUsageBytes := []byte{byte(S2KUsageConventionEncryptedSha1)}

	err = serializeHeader(w, ptype, len(publicKeyBytes)+len(s2kUsageBytes)+len(encryptionHeaderBytes)+len(initialVectorBytes)+len(encryptedPrivateKeyAndSha1Bytes))

	if err != nil {
		return
	}
	_, err = w.Write(publicKeyBytes)
	if err != nil {
		return
	}

	_, err = w.Write(s2kUsageBytes)
	if err != nil {
		return
	}

	_, err = w.Write(encryptionHeaderBytes)
	if err != nil {
		return
	}

	_, err = w.Write(initialVectorBytes)
	if err != nil {
		return
	}

	_, err = w.Write(encryptedPrivateKeyAndSha1Bytes)
	if err != nil {
		return
	}

	return
}

func getPrivateKeyPacketType(pk *PrivateKey) (ptype packetType) {
	if pk.IsSubkey {
		ptype = packetTypePrivateSubkey
	} else {
		ptype = packetTypePrivateKey
	}
	return
}

func getRandomBytes(count int, rand io.Reader) (randomBytes []byte, err error) {
	randomBytes = make([]byte, count)
	_, err = rand.Read(randomBytes)
	return randomBytes, err
}

func makeSha1Hash(inputBytes []byte) []byte {
	h := sha1.New()
	h.Write(inputBytes)
	return h.Sum(nil)
}

func symmetricEncrypt(
	inputPlaintext []byte,
	cipherFunc CipherFunction,
	symmetricKey []byte,
	initialVector []byte,
) (ciphertext []byte, err error) {

	if cipherFunc.KeySize() != len(symmetricKey) {
		return nil, errors.InvalidArgumentError(fmt.Sprintf("makeSymmetricEncryptor: bad key length %v, expected %v for algorithm %v", len(symmetricKey), cipherFunc.KeySize(), cipherFunc))
	}

	if len(initialVector) != cipherFunc.blockSize() {
		return nil, errors.InvalidArgumentError("makeSymmetricEncryptor: bad length IV")
	}

	block := cipherFunc.new(symmetricKey)

	encryptorStream := cipher.NewCFBEncrypter(block, initialVector)

	ciphertext = make([]byte, len(inputPlaintext))
	encryptorStream.XORKeyStream(ciphertext, inputPlaintext)

	return ciphertext, nil
}

func getS2KHeaderAndSymmetricKey(password []byte, cipherFunc CipherFunction) (header []byte, symmetricKey []byte, err error) {
	rand := rand.Reader // TODO: use config.Random() or pass in rand

	keySize := cipherFunc.KeySize()

	if keySize == 0 {
		return nil, nil, errors.UnsupportedError("unknown cipher: " + strconv.Itoa(int(cipherFunc)))
	}

	s2kBuf := new(bytes.Buffer)
	passwordDerivedKey := make([]byte, keySize)

	config := s2k.Config{
		S2KCount: s2k.S2KCountMax,
		Hash:     crypto.SHA256,
	}

	// s2k.Serialize salts and stretches the passphrase, and writes the
	// resulting key to passwordDerivedKey and the s2k descriptor to s2kBuf.

	err = s2k.Serialize(
		s2kBuf,
		passwordDerivedKey,
		rand,
		password,
		&config,
	)
	if err != nil {
		return
	}

	headerBuf := bytes.NewBuffer(nil)

	_, err = headerBuf.Write([]byte{byte(cipherFunc)})
	if err != nil {
		return
	}

	_, err = headerBuf.Write(s2kBuf.Bytes())
	if err != nil {
		return
	}

	return headerBuf.Bytes(), passwordDerivedKey, nil
}

func getPublicKeyBytes(pk *PrivateKey) (b []byte, err error) {
	buf := bytes.NewBuffer(nil)
	err = pk.PublicKey.serializeWithoutHeaders(buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// TODO: remove this, since it's only used for the unencrypted case
func getPrivateKeyHeaderBytes(pk *PrivateKey) (b []byte, err error) {
	buf := bytes.NewBuffer(nil)
	buf.WriteByte(S2KUsageConventionUnencrypted)
	return buf.Bytes(), nil
}

func getPrivateKeyBytes(pk *PrivateKey) (b []byte, err error) {
	privateKeyBuf := bytes.NewBuffer(nil)

	switch priv := pk.PrivateKey.(type) {
	case *rsa.PrivateKey:
		err = serializeRSAPrivateKey(privateKeyBuf, priv)
	case *dsa.PrivateKey:
		err = serializeDSAPrivateKey(privateKeyBuf, priv)
	case *elgamal.PrivateKey:
		err = serializeElGamalPrivateKey(privateKeyBuf, priv)
	case *ecdsa.PrivateKey:
		err = serializeECDSAPrivateKey(privateKeyBuf, priv)
	default:
		err = errors.InvalidArgumentError("unknown private key type")
	}
	if err != nil {
		return nil, err
	}
	return privateKeyBuf.Bytes(), nil
}

func getChecksumBytes(privateKeyBytes []byte) [2]byte {
	checksum := mod64kHash(privateKeyBytes)
	var checksumBytes [2]byte
	checksumBytes[0] = byte(checksum >> 8)
	checksumBytes[1] = byte(checksum)
	return checksumBytes
}

func serializeRSAPrivateKey(w io.Writer, priv *rsa.PrivateKey) error {
	err := writeBig(w, priv.D)
	if err != nil {
		return err
	}
	err = writeBig(w, priv.Primes[1])
	if err != nil {
		return err
	}
	err = writeBig(w, priv.Primes[0])
	if err != nil {
		return err
	}
	return writeBig(w, priv.Precomputed.Qinv)
}

func serializeDSAPrivateKey(w io.Writer, priv *dsa.PrivateKey) error {
	return writeBig(w, priv.X)
}

func serializeElGamalPrivateKey(w io.Writer, priv *elgamal.PrivateKey) error {
	return writeBig(w, priv.X)
}

func serializeECDSAPrivateKey(w io.Writer, priv *ecdsa.PrivateKey) error {
	return writeBig(w, priv.D)
}

// Decrypt decrypts an encrypted private key using a passphrase.
func (pk *PrivateKey) Decrypt(passphrase []byte) error {
	if !pk.Encrypted {
		return nil
	}

	key := make([]byte, pk.cipher.KeySize())
	pk.s2k(key, passphrase)
	block := pk.cipher.new(key)
	cfb := cipher.NewCFBDecrypter(block, pk.iv)

	data := make([]byte, len(pk.encryptedData))
	cfb.XORKeyStream(data, pk.encryptedData)

	if pk.sha1Checksum {
		if len(data) < sha1.Size {
			return errors.StructuralError("truncated private key data")
		}
		h := sha1.New()
		h.Write(data[:len(data)-sha1.Size])
		sum := h.Sum(nil)
		if !bytes.Equal(sum, data[len(data)-sha1.Size:]) {
			return errors.StructuralError("private key sha1 failure")
		}
		data = data[:len(data)-sha1.Size]
	} else {
		if len(data) < 2 {
			return errors.StructuralError("truncated private key data")
		}
		var sum uint16
		for i := 0; i < len(data)-2; i++ {
			sum += uint16(data[i])
		}
		if data[len(data)-2] != uint8(sum>>8) ||
			data[len(data)-1] != uint8(sum) {
			return errors.StructuralError("private key checksum failure")
		}
		data = data[:len(data)-2]
	}

	return pk.parsePrivateKey(data)
}

func (pk *PrivateKey) parsePrivateKey(data []byte) (err error) {
	switch pk.PublicKey.PubKeyAlgo {
	case PubKeyAlgoRSA, PubKeyAlgoRSASignOnly, PubKeyAlgoRSAEncryptOnly:
		return pk.parseRSAPrivateKey(data)
	case PubKeyAlgoDSA:
		return pk.parseDSAPrivateKey(data)
	case PubKeyAlgoElGamal:
		return pk.parseElGamalPrivateKey(data)
	case PubKeyAlgoECDSA:
		return pk.parseECDSAPrivateKey(data)
	}
	panic("impossible")
}

func (pk *PrivateKey) parseRSAPrivateKey(data []byte) (err error) {
	rsaPub := pk.PublicKey.PublicKey.(*rsa.PublicKey)
	rsaPriv := new(rsa.PrivateKey)
	rsaPriv.PublicKey = *rsaPub

	buf := bytes.NewBuffer(data)
	d, _, err := readMPI(buf)
	if err != nil {
		return
	}
	p, _, err := readMPI(buf)
	if err != nil {
		return
	}
	q, _, err := readMPI(buf)
	if err != nil {
		return
	}

	rsaPriv.D = new(big.Int).SetBytes(d)
	rsaPriv.Primes = make([]*big.Int, 2)
	rsaPriv.Primes[0] = new(big.Int).SetBytes(p)
	rsaPriv.Primes[1] = new(big.Int).SetBytes(q)
	if err := rsaPriv.Validate(); err != nil {
		return err
	}
	rsaPriv.Precompute()
	pk.PrivateKey = rsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseDSAPrivateKey(data []byte) (err error) {
	dsaPub := pk.PublicKey.PublicKey.(*dsa.PublicKey)
	dsaPriv := new(dsa.PrivateKey)
	dsaPriv.PublicKey = *dsaPub

	buf := bytes.NewBuffer(data)
	x, _, err := readMPI(buf)
	if err != nil {
		return
	}

	dsaPriv.X = new(big.Int).SetBytes(x)
	pk.PrivateKey = dsaPriv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseElGamalPrivateKey(data []byte) (err error) {
	pub := pk.PublicKey.PublicKey.(*elgamal.PublicKey)
	priv := new(elgamal.PrivateKey)
	priv.PublicKey = *pub

	buf := bytes.NewBuffer(data)
	x, _, err := readMPI(buf)
	if err != nil {
		return
	}

	priv.X = new(big.Int).SetBytes(x)
	pk.PrivateKey = priv
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}

func (pk *PrivateKey) parseECDSAPrivateKey(data []byte) (err error) {
	ecdsaPub := pk.PublicKey.PublicKey.(*ecdsa.PublicKey)

	buf := bytes.NewBuffer(data)
	d, _, err := readMPI(buf)
	if err != nil {
		return
	}

	pk.PrivateKey = &ecdsa.PrivateKey{
		PublicKey: *ecdsaPub,
		D:         new(big.Int).SetBytes(d),
	}
	pk.Encrypted = false
	pk.encryptedData = nil

	return nil
}
