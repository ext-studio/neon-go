package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Reverse hex
func Reverse(str string) string {
	pb, err := hex.DecodeString(str)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(ReverseArray(pb))
}

// FromInt2Hex parse int value to hex string
func FromInt2Hex(num int64, size int64, littleEnd bool) string {
	if num < 0 {
		return ""
	}
	if size%1 != 0 {
		return ""
	}
	size = size * 2
	hexstring := fmt.Sprintf("%x", num)
	if (int64)(len(hexstring))%size != 0 {
		hexstring = (strings.Repeat("0", (int)(size)) + hexstring)[len(hexstring):]
	}
	if littleEnd {
		hexstring = Reverse(hexstring)
	}
	return hexstring
}

// FromInt2VarInt parse int value to var int hex string
func FromInt2VarInt(num int64) string {
	if num < 0xfd {
		return FromInt2Hex(num, 1, false)
	} else if num <= 0xffff {
		// uint16
		return "fd" + FromInt2Hex(num, 2, true)
	} else if num <= 0xffffffff {
		// uint32
		return "fe" + FromInt2Hex(num, 4, true)
	} else {
		// uint64
		return "ff" + FromInt2Hex(num, 8, true)
	}
}

// FromNumber2Fixed parse number to fixed hex string
func FromNumber2Fixed(num float64, size int64) string {
	fixedStr := fmt.Sprintf("%.8f", num)
	return Reverse(fixedStr)[0 : size*2]
}

// FromString parse from string
func FromString(str string) string {
	return hex.EncodeToString([]byte(str))
}

// ToHash256 parse hex by SHA256 twice
func ToHash256(hex string) string {
	sha := sha256.New()
	sha.Write([]byte(hex))
	hash := sha.Sum(nil)
	sha.Reset()
	sha.Write(hash)
	return (string)(sha.Sum(nil))
}

// ToXor make xor operate to given hexes
func ToXor(hex1, hex2 string) string {
	a, erra := hex.DecodeString(hex1)
	b, errb := hex.DecodeString(hex2)
	if erra != nil || errb != nil {
		return ""
	}
	if len(a) != len(b) {
		panic("cannot XOR non equal length arrays")
	}
	dst := make([]byte, len(a))
	for i := 0; i < len(dst); i++ {
		dst[i] = a[i] ^ b[i]
	}
	return hex.EncodeToString(dst)
}
