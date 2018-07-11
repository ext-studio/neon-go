package transaction

import (
	"strings"

	"github.com/yitimo/neon-go/libs/hex"
)

// GenerateScript parse given params to script
func GenerateScript(hash string, operation string, args []interface{}, useTailCall bool) string {
	script := Script{"", hash, operation, args}
	script.serielize(useTailCall)
	return script.script
}

// GenerateScriptByString parse given string params to script
func GenerateScriptByString(hash string, operation string, args []string, useTailCall bool) string {
	script := Script{"", hash, operation, []interface{}{args}}
	script.serielize(useTailCall)
	return script.script
}

// ForAmount generate amount value
func ForAmount(value float64) string {
	target := (int64)(value * 100000000)
	if target == -1 {
		return Add(PUSHM1, "")
	}
	if target == 0 {
		return Add(PUSH0, "")
	}
	if target > 0 && target <= 16 {
		return Add(PUSH1-1+target, "")
	}
	hexstring := hex.Int2HexInt((int64)(target))
	return AddString(hex.Reverse(strings.Repeat("0", 16-len(hexstring)) + hexstring))
}
