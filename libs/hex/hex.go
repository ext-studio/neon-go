package hex

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/ext-studio/neon-go/libs/utils"
)

/*FromVarInt parse int value to hex string, add var prefix to it if needed
* 将整型数值转为 hex 字符串, 并智能添加符号位前缀
**/
func FromVarInt(value int64) string {
	if value < 0xfd {
		return FromInt(value, 1, false)
	} else if value <= 0xffff {
		// uint16
		return "fd" + FromInt(value, 2, true)
	} else if value <= 0xffffffff {
		// uint32
		return "fe" + FromInt(value, 4, true)
	} else {
		// uint64
		return "ff" + FromInt(value, 8, true)
	}
}

/*FromInt parse int value to hex string by given size and end
* 将整型数值转为 hex 字符串
**/
func FromInt(num int64, size int, littleEnd bool) string {
	if num < 0 {
		return ""
	}
	if size%1 != 0 {
		return ""
	}
	size = size * 2
	hexstring := fmt.Sprintf("%x", num)
	if len(hexstring)%size != 0 {
		hexstring = (strings.Repeat("0", (int)(size)) + hexstring)[len(hexstring):]
	}
	if littleEnd {
		hexstring = Reverse(hexstring)
	}
	return hexstring
}

/*Reverse reverse a hex string
* 反向 hex 字符串
**/
func Reverse(hexStr string) string {
	pb, err := hex.DecodeString(hexStr)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(utils.ReverseArray(pb))
}

/*ToFixedNum parse number to 16 bytes fixed hex string
* 用于格式化 NEP5 转账中的金额字段 默认精度为8
**/
func ToFixedNum(num float64, decimal int) string {
	decimal = 8
	num *= math.Pow10(decimal)
	value := FromVarInt((int64)(num))
	return Reverse(strings.Repeat("0", 16-len(value)) + value)
}

/*Hash256 encode hex string by sha256 twice
* 对字符串进行两次 SHA256 序列化操作
**/
func Hash256(hexStr string) string {
	sha := sha256.New()
	sha.Write([]byte(hexStr))
	hash := sha.Sum(nil)
	sha.Reset()
	sha.Write(hash)
	return (string)(sha.Sum(nil))
}

/*FromString parse common string to hex string
* 将字符串转为十六进制字符串(取字符ASCII编码)
**/
func FromString(src string) string {
	rs := ""
	for _, c := range src {
		rs += FromInt((int64)(c), 1, false)
	}
	return rs
}

/*FromInt2HexInt parse decimal int to hex string int and add 0 if needed
* 将十进制数值转为十六进制, 若位数不够则补零
**/
func Int2HexInt(num int64) string {
	rs := fmt.Sprintf("%x", num)
	if len(rs)%2 == 1 {
		return "0" + rs
	}
	return rs
}

/*Xor xor operate for given two hex strings
* 对两个 hex 字符串执行 xor 操作
**/
func Xor(hex1, hex2 string) string {
	a, erra := hex.DecodeString(hex1)
	b, errb := hex.DecodeString(hex2)
	if erra != nil || errb != nil {
		return ""
	}
	if len(a) != len(b) {
		return ""
	}
	dst := make([]byte, len(a))
	for i := 0; i < len(dst); i++ {
		dst[i] = a[i] ^ b[i]
	}
	return hex.EncodeToString(dst)
}
