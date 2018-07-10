package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
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

var one = big.NewInt(1)
var nepHeader = []byte{0x01, 0x42}

// Generate new random private key string
func Generate() string {
	c := crypto.NewEllipticCurve()
	b := make([]byte, c.N.BitLen()/8+8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	d := new(big.Int).SetBytes(b)
	d.Mod(d, new(big.Int).Sub(c.N, big.NewInt(1)))
	d.Add(d, big.NewInt(1))

	return hex.EncodeToString(d.Bytes())
}

// Signature sign a tx by given WIF key
func Signature(txhash, wif string) string {
	priv := Wif2Priv(wif)
	if priv == "" {
		return ""
	}
	privAB, errp := hex.DecodeString(priv)
	if errp != nil {
		return ""
	}
	txhashAB, errt := hex.DecodeString(txhash)
	if errt != nil {
		return ""
	}
	sha := sha256.New()
	sha.Write(txhashAB)
	hashAB := sha.Sum(nil)

	privKey := new(ecdsa.PrivateKey)
	privKey.PublicKey.Curve = elliptic.P256()
	privKey.D = new(big.Int).SetBytes(privAB)
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(privAB)

	// use hashAB and privKey
	c := privKey.PublicKey.Curve
	N := c.Params().N

	var r, s *big.Int

	generateSecret(N, privKey.D, sha256.New, hashAB, func(k *big.Int) bool {
		inv := new(big.Int).ModInverse(k, N)
		r, _ = privKey.Curve.ScalarBaseMult(k.Bytes())
		r.Mod(r, N)

		if r.Sign() == 0 {
			return false
		}

		e := hashToInt(hashAB, c)
		s = new(big.Int).Mul(privKey.D, r)
		s.Add(s, e)
		s.Mul(s, inv)
		s.Mod(s, N)

		return s.Sign() != 0
	})

	// use r & s here

	params := privKey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)

	return hex.EncodeToString(signature)
}

// Priv2Pub get public key from private key
func Priv2Pub(priv string) string {
	pb, err := hex.DecodeString(priv)
	if err != nil {
		return ""
	}
	var (
		c = crypto.NewEllipticCurve()
		q = new(big.Int).SetBytes(pb)
	)
	point := c.ScalarBaseMult(q)
	if !c.IsOnCurve(point) {
		return ""
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
	return hex.EncodeToString(b)
}

// Pub2Addr get address from public key
func Pub2Addr(pub string) string {
	b, err := signature(pub)
	if err != nil {
		return ""
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

	return address
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
func Priv2Addr(priv string) string {
	pub := Priv2Pub(priv)
	return Pub2Addr(pub)
}

// Priv2Wif get wif from private key
func Priv2Wif(priv string) string {
	if len(priv) != 64 {
		return ""
	}
	pb, err := hex.DecodeString(priv)
	if err != nil {
		return ""
	}
	buf := new(bytes.Buffer)
	buf.WriteByte(wifVersion)
	buf.Write(pb)
	buf.WriteByte(0x01)

	return crypto.Base58CheckEncode(buf.Bytes())
}

// Wif2Priv get wif from private key
func Wif2Priv(wif string) string {
	b, err := crypto.Base58CheckDecode(wif)
	if err != nil {
		return ""
	}
	// Derive the PrivateKey.
	if err != nil {
		return ""
	}
	// This is an uncompressed WIF
	if len(b) == 33 {
		return hex.EncodeToString(b[1:33])
	}
	if len(b) != 34 {
		return ""
	}
	// Check the compression flag.
	if b[33] != 0x01 {
		return ""
	}
	return hex.EncodeToString(b[1:33])
}

// Wif2Addr get address from wif
func Wif2Addr(wif string) string {
	priv := Wif2Priv(wif)
	return Priv2Addr(priv)
}

// NEP2Encode get key from wif
func NEP2Encode(wif, pwd string) string {
	addr := Wif2Addr(wif)
	priv := Wif2Priv(wif)
	privBytes, berr := hex.DecodeString(priv)
	if berr != nil {
		return ""
	}
	addrHash := addrToHash(addr)[0:4]
	phraseNorm := norm.NFC.Bytes([]byte(pwd))
	derivedKey, err := scrypt.Key(phraseNorm, addrHash, n, r, p, keyLen)
	if err != nil {
		return ""
	}
	derivedKey1 := derivedKey[:32]
	derivedKey2 := derivedKey[32:]
	xr := xor(privBytes, derivedKey1)
	encrypted, err := crypto.AESEncrypt(xr, derivedKey2)
	if err != nil {
		return ""
	}
	buf := new(bytes.Buffer)
	buf.Write(nepHeader)
	buf.WriteByte(nepFlag)
	buf.Write(addrHash)
	buf.Write(encrypted)
	if buf.Len() != 39 {
		return ""
	}
	return crypto.Base58CheckEncode(buf.Bytes())
}

// NEP2Decode get wif from key
func NEP2Decode(key, pwd string) string {
	b, err := crypto.Base58CheckDecode(key)
	if err != nil {
		return ""
	}
	if err := validateNEP2Format(b); err != nil {
		return ""
	}
	addrHash := b[3:7]
	// Normalize the passphrase according to the NFC standard.
	phraseNorm := norm.NFC.Bytes([]byte(pwd))
	derivedKey, err := scrypt.Key(phraseNorm, addrHash, n, r, p, keyLen)
	if err != nil {
		return ""
	}
	derivedKey1 := derivedKey[:32]
	derivedKey2 := derivedKey[32:]
	encryptedBytes := b[7:]
	decrypted, err := crypto.AESDecrypt(encryptedBytes, derivedKey2)
	if err != nil {
		return ""
	}
	privBytes := xor(decrypted, derivedKey1)

	if !compareAddressHash(privBytes, addrHash) {
		return ""
	}
	return Priv2Wif(hex.EncodeToString(privBytes))
}

// Addr2Script get scripthash from address
func Addr2Script(address string) string {
	b, err := crypto.Base58CheckDecode(address)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b[1:21])
}

// Script2Addr get address from scripthash
func Script2Addr(script string) string {
	bs, err := hex.DecodeString(script)
	if err != nil {
		return ""
	}
	b := append([]byte{0x17}, bs...)
	return crypto.Base58CheckEncode(b)
}

func compareAddressHash(priv []byte, hash []byte) bool {
	address := Priv2Addr(hex.EncodeToString(priv))
	if address == "" {
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

// mac returns an HMAC of the given key and message.
func mac(alg func() hash.Hash, k, m, buf []byte) []byte {
	h := hmac.New(alg, k)
	h.Write(m)
	return h.Sum(buf[:0])
}

// https://tools.ietf.org/html/rfc6979#section-2.3.2
func bits2int(in []byte, qlen int) *big.Int {
	vlen := len(in) * 8
	v := new(big.Int).SetBytes(in)
	if vlen > qlen {
		v = new(big.Int).Rsh(v, uint(vlen-qlen))
	}
	return v
}

// https://tools.ietf.org/html/rfc6979#section-2.3.3
func int2octets(v *big.Int, rolen int) []byte {
	out := v.Bytes()

	// pad with zeros if it's too short
	if len(out) < rolen {
		out2 := make([]byte, rolen)
		copy(out2[rolen-len(out):], out)
		return out2
	}

	// drop most significant bytes if it's too long
	if len(out) > rolen {
		out2 := make([]byte, rolen)
		copy(out2, out[len(out)-rolen:])
		return out2
	}

	return out
}

// https://tools.ietf.org/html/rfc6979#section-2.3.4
func bits2octets(in []byte, q *big.Int, qlen, rolen int) []byte {
	z1 := bits2int(in, qlen)
	z2 := new(big.Int).Sub(z1, q)
	if z2.Sign() < 0 {
		return int2octets(z1, rolen)
	}
	return int2octets(z2, rolen)
}

func generateSecret(q, x *big.Int, alg func() hash.Hash, hash []byte, test func(*big.Int) bool) {
	qlen := q.BitLen()
	holen := alg().Size()
	rolen := (qlen + 7) >> 3
	bx := append(int2octets(x, rolen), bits2octets(hash, q, qlen, rolen)...)

	// Step B
	v := bytes.Repeat([]byte{0x01}, holen)

	// Step C
	k := bytes.Repeat([]byte{0x00}, holen)

	// Step D
	k = mac(alg, k, append(append(v, 0x00), bx...), k)

	// Step E
	v = mac(alg, k, v, v)

	// Step F
	k = mac(alg, k, append(append(v, 0x01), bx...), k)

	// Step G
	v = mac(alg, k, v, v)

	// Step H
	for {
		// Step H1
		var t []byte

		// Step H2
		for len(t) < qlen/8 {
			v = mac(alg, k, v, v)
			t = append(t, v...)
		}

		// Step H3
		secret := bits2int(t, qlen)
		if secret.Cmp(one) >= 0 && secret.Cmp(q) < 0 && test(secret) {
			return
		}
		k = mac(alg, k, append(v, 0x00), k)
		v = mac(alg, k, v, v)
	}
}

// copied from crypto/ecdsa
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}
