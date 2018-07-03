package wallet

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/yitimo/neon-go/libs/crypto"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

const (
	// wifVersion is the version used to decode and encode WIF keys.
	wifVersion = 0x80
	n          = 16384
	r          = 8
	p          = 8
	keyLen     = 64
	nepFlag    = 0xe0
)

var nepHeader = []byte{0x01, 0x42}

// Generate new random private key string
func Generate() (string, error) {
	c := crypto.NewEllipticCurve()
	b := make([]byte, c.N.BitLen()/8+8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	d := new(big.Int).SetBytes(b)
	d.Mod(d, new(big.Int).Sub(c.N, big.NewInt(1)))
	d.Add(d, big.NewInt(1))

	return hex.EncodeToString(d.Bytes()), nil
}

// Priv2Pub get public key from private key
func Priv2Pub(priv string) (string, error) {
	pb, err := hex.DecodeString(priv)
	if err != nil {
		return "", err
	}
	var (
		c = crypto.NewEllipticCurve()
		q = new(big.Int).SetBytes(pb)
	)
	point := c.ScalarBaseMult(q)
	if !c.IsOnCurve(point) {
		return "", errors.New("failed to derive public key using elliptic curve")
	}
	bx := point.X.Bytes()
	padded := append(
		bytes.Repeat(
			[]byte{0x00},
			32-len(bx),
		),
		bx...,
	)
	prefix := []byte{0x03}
	if point.Y.Bit(0) == 0 {
		prefix = []byte{0x02}
	}
	b := append(prefix, padded...)
	return hex.EncodeToString(b), nil
}

// Pub2Addr get address from public key
func Pub2Addr(pub string) (string, error) {
	b, err := signature(pub)
	if err != nil {
		return "", err
	}
	b = append([]byte{0x17}, b...)

	sha := sha256.New()
	sha.Write(b)
	hash := sha.Sum(nil)

	sha.Reset()
	sha.Write(hash)
	hash = sha.Sum(nil)

	b = append(b, hash[0:4]...)

	address := crypto.Base58Encode(b)

	return address, nil
}

func signature(pub string) ([]byte, error) {
	b, err := hex.DecodeString(pub)
	if err != nil {
		return nil, err
	}

	b = append([]byte{0x21}, b...)
	b = append(b, 0xAC)

	sha := sha256.New()
	sha.Write(b)
	hash := sha.Sum(nil)

	ripemd := ripemd160.New()
	ripemd.Reset()
	ripemd.Write(hash)
	hash = ripemd.Sum(nil)

	return hash, nil
}

// Priv2Addr get address from private key
func Priv2Addr(priv string) (string, error) {
	pub, err := Priv2Pub(priv)
	if err != nil {
		return "", err
	}
	return Pub2Addr(pub)
}

// Priv2Wif get wif from private key
func Priv2Wif(priv string) (string, error) {
	if len(priv) != 64 {
		return "", fmt.Errorf("invalid private key length: %d", len(priv))
	}
	pb, err := hex.DecodeString(priv)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	buf.WriteByte(wifVersion)
	buf.Write(pb)
	buf.WriteByte(0x01)

	return crypto.Base58CheckEncode(buf.Bytes()), nil
}

// Wif2Priv get wif from private key
func Wif2Priv(wif string) (string, error) {
	b, err := crypto.Base58CheckDecode(wif)
	if err != nil {
		return "", err
	}
	// Derive the PrivateKey.
	if err != nil {
		return "", err
	}
	// This is an uncompressed WIF
	if len(b) == 33 {
		return hex.EncodeToString(b[1:33]), nil
	}
	if len(b) != 34 {
		return "", fmt.Errorf("invalid WIF length: %d expecting 34", len(b))
	}
	// Check the compression flag.
	if b[33] != 0x01 {
		return "", fmt.Errorf("invalid compression flag %d expecting %d", b[34], 0x01)
	}
	return hex.EncodeToString(b[1:33]), nil
}

// Wif2Addr get address from wif
func Wif2Addr(wif string) (string, error) {
	priv, err := Wif2Priv(wif)
	if err != nil {
		return "", err
	}
	return Priv2Addr(priv)
}

// NEP2Encode get key from wif
func NEP2Encode(wif, pwd string) (string, error) {
	addr, aerr := Wif2Addr(wif)
	if aerr != nil {
		return "", aerr
	}
	priv, perr := Wif2Priv(wif)
	if perr != nil {
		return "", perr
	}
	privBytes, berr := hex.DecodeString(priv)
	if berr != nil {
		return "", berr
	}
	addrHash := addrToHash(addr)[0:4]
	phraseNorm := norm.NFC.Bytes([]byte(pwd))
	derivedKey, err := scrypt.Key(phraseNorm, addrHash, n, r, p, keyLen)
	if err != nil {
		return "", err
	}
	derivedKey1 := derivedKey[:32]
	derivedKey2 := derivedKey[32:]
	xr := xor(privBytes, derivedKey1)
	encrypted, err := crypto.AESEncrypt(xr, derivedKey2)
	if err != nil {
		return "", err
	}
	fmt.Printf("\n\n\n%x  %x  %x\n\n\n", privBytes, xr, encrypted)
	buf := new(bytes.Buffer)
	buf.Write(nepHeader)
	buf.WriteByte(nepFlag)
	buf.Write(addrHash)
	buf.Write(encrypted)
	if buf.Len() != 39 {
		return "", fmt.Errorf("invalid buffer length: expecting 39 bytes got %d", buf.Len())
	}
	return crypto.Base58CheckEncode(buf.Bytes()), nil
}

// NEP2Decode get wif from key
func NEP2Decode(key, pwd string) (string, error) {
	b, err := crypto.Base58CheckDecode(key)
	if err != nil {
		return "", err
	}
	if err := validateNEP2Format(b); err != nil {
		return "", err
	}
	addrHash := b[3:7]
	// Normalize the passphrase according to the NFC standard.
	phraseNorm := norm.NFC.Bytes([]byte(pwd))
	derivedKey, err := scrypt.Key(phraseNorm, addrHash, n, r, p, keyLen)
	if err != nil {
		return "", err
	}
	derivedKey1 := derivedKey[:32]
	derivedKey2 := derivedKey[32:]
	encryptedBytes := b[7:]
	decrypted, err := crypto.AESDecrypt(encryptedBytes, derivedKey2)
	if err != nil {
		return "", err
	}
	privBytes := xor(decrypted, derivedKey1)

	fmt.Printf("\n\n\n%x  %x  %x\n\n\n", privBytes, decrypted, encryptedBytes)

	if !compareAddressHash(privBytes, addrHash) {
		return "", errors.New("password mismatch")
	}
	return Priv2Wif(hex.EncodeToString(privBytes))
}

// Addr2Script get scripthash from address
func Addr2Script(address string) (string, error) {
	b, err := crypto.Base58CheckDecode(address)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b[1:21]), nil
}

// Script2Addr get address from scripthash
func Script2Addr(script string) (string, error) {
	bs, err := hex.DecodeString(script)
	if err != nil {
		return "", err
	}
	b := append([]byte{0x17}, bs...)
	return crypto.Base58CheckEncode(b), nil
}

func compareAddressHash(priv []byte, hash []byte) bool {
	address, err := Priv2Addr(hex.EncodeToString(priv))
	if err != nil {
		return false
	}
	addrHash := addrToHash(address)[0:4]
	return bytes.Compare(addrHash, hash) == 0
}

func validateNEP2Format(b []byte) error {
	if len(b) != 39 {
		return fmt.Errorf("invalid length: expecting 39 got %d", len(b))
	}
	if b[0] != 0x01 {
		return fmt.Errorf("invalid byte sequence: expecting 0x01 got 0x%02x", b[0])
	}
	if b[1] != 0x42 {
		return fmt.Errorf("invalid byte sequence: expecting 0x42 got 0x%02x", b[1])
	}
	if b[2] != 0xe0 {
		return fmt.Errorf("invalid byte sequence: expecting 0xe0 got 0x%02x", b[2])
	}
	return nil
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("cannot XOR non equal length arrays")
	}
	dst := make([]byte, len(a))
	for i := 0; i < len(dst); i++ {
		dst[i] = a[i] ^ b[i]
	}
	return dst
}

func addrToHash(addr string) []byte {
	sha := sha256.New()
	sha.Write([]byte(addr))
	hash := sha.Sum(nil)
	sha.Reset()
	sha.Write(hash)
	return sha.Sum(nil)
}
