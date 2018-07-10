package transaction

import (
	"strings"

	"github.com/yitimo/neon-go/libs/utils"
)

const (
	// Constants
	PUSH0       = 0x00 // An empty array of bytes is pushed onto the stack.
	PUSHF       = PUSH0
	PUSHBYTES1  = 0x01 // 0x01-0x4B The next  bytes is data to be pushed onto the stack
	PUSHBYTES75 = 0x4B
	PUSHDATA1   = 0x4C // The next byte contains the number of bytes to be pushed onto the stack.
	PUSHDATA2   = 0x4D // The next two bytes contain the number of bytes to be pushed onto the stack.
	PUSHDATA4   = 0x4E // The next four bytes contain the number of bytes to be pushed onto the stack.
	PUSHM1      = 0x4F // The number -1 is pushed onto the stack.
	PUSH1       = 0x51 // The number 1 is pushed onto the stack.
	PUSHT       = PUSH1
	PUSH2       = 0x52 // The number 2 is pushed onto the stack.
	PUSH3       = 0x53 // The number 3 is pushed onto the stack.
	PUSH4       = 0x54 // The number 4 is pushed onto the stack.
	PUSH5       = 0x55 // The number 5 is pushed onto the stack.
	PUSH6       = 0x56 // The number 6 is pushed onto the stack.
	PUSH7       = 0x57 // The number 7 is pushed onto the stack.
	PUSH8       = 0x58 // The number 8 is pushed onto the stack.
	PUSH9       = 0x59 // The number 9 is pushed onto the stack.
	PUSH10      = 0x5A // The number 10 is pushed onto the stack.
	PUSH11      = 0x5B // The number 11 is pushed onto the stack.
	PUSH12      = 0x5C // The number 12 is pushed onto the stack.
	PUSH13      = 0x5D // The number 13 is pushed onto the stack.
	PUSH14      = 0x5E // The number 14 is pushed onto the stack.
	PUSH15      = 0x5F // The number 15 is pushed onto the stack.
	PUSH16      = 0x60 // The number 16 is pushed onto the stack.

	// Flow control
	NOP      = 0x61 // Does nothing.
	JMP      = 0x62
	JMPIF    = 0x63
	JMPIFNOT = 0x64
	CALL     = 0x65
	RET      = 0x66
	APPCALL  = 0x67
	SYSCALL  = 0x68
	TAILCALL = 0x69

	// Stack
	DUPFROMALTSTACK = 0x6A
	TOALTSTACK      = 0x6B // Puts the input onto the top of the alt stack. Removes it from the main stack.
	FROMALTSTACK    = 0x6C // Puts the input onto the top of the main stack. Removes it from the alt stack.
	XDROP           = 0x6D
	XSWAP           = 0x72
	XTUCK           = 0x73
	DEPTH           = 0x74 // Puts the number of stack items onto the stack.
	DROP            = 0x75 // Removes the top stack item.
	DUP             = 0x76 // Duplicates the top stack item.
	NIP             = 0x77 // Removes the second-to-top stack item.
	OVER            = 0x78 // Copies the second-to-top stack item to the top.
	PICK            = 0x79 // The item n back in the stack is copied to the top.
	ROLL            = 0x7A // The item n back in the stack is moved to the top.
	ROT             = 0x7B // The top three items on the stack are rotated to the left.
	SWAP            = 0x7C // The top two items on the stack are swapped.
	TUCK            = 0x7D // The item at the top of the stack is copied and inserted before the second-to-top item.

	// Splice
	CAT    = 0x7E // Concatenates two strings.
	SUBSTR = 0x7F // Returns a section of a string.
	LEFT   = 0x80 // Keeps only characters left of the specified point in a string.
	RIGHT  = 0x81 // Keeps only characters right of the specified point in a string.
	SIZE   = 0x82 // Returns the length of the input string.

	// Bitwise logic
	INVERT = 0x83 // Flips all of the bits in the input.
	AND    = 0x84 // Boolean and between each bit in the inputs.
	OR     = 0x85 // Boolean or between each bit in the inputs.
	XOR    = 0x86 // Boolean exclusive or between each bit in the inputs.
	EQUAL  = 0x87 // Returns 1 if the inputs are exactly equal 0 otherwise.
	//OP_EQUALVERIFY  = 0x88 // Same as OP_EQUAL but runs OP_VERIFY afterward.
	//OP_RESERVED1  = 0x89 // Transaction is invalid unless occuring in an unexecuted OP_IF branch
	//OP_RESERVED2  = 0x8A // Transaction is invalid unless occuring in an unexecuted OP_IF branch

	// Arithmetic
	// Note: Arithmetic inputs are limited to signed 32-bit integers but may overflow their output.
	INC         = 0x8B // 1 is added to the input.
	DEC         = 0x8C // 1 is subtracted from the input.
	SIGN        = 0x8D
	NEGATE      = 0x8F // The sign of the input is flipped.
	ABS         = 0x90 // The input is made positive.
	NOT         = 0x91 // If the input is 0 or 1 it is flipped. Otherwise the output will be 0.
	NZ          = 0x92 // Returns 0 if the input is 0. 1 otherwise.
	ADD         = 0x93 // a is added to b.
	SUB         = 0x94 // b is subtracted from a.
	MUL         = 0x95 // a is multiplied by b.
	DIV         = 0x96 // a is divided by b.
	MOD         = 0x97 // Returns the remainder after dividing a by b.
	SHL         = 0x98 // Shifts a left b bits preserving sign.
	SHR         = 0x99 // Shifts a right b bits preserving sign.
	BOOLAND     = 0x9A // If both a and b are not 0 the output is 1. Otherwise 0.
	BOOLOR      = 0x9B // If a or b is not 0 the output is 1. Otherwise 0.
	NUMEQUAL    = 0x9C // Returns 1 if the numbers are equal 0 otherwise.
	NUMNOTEQUAL = 0x9E // Returns 1 if the numbers are not equal 0 otherwise.
	LT          = 0x9F // Returns 1 if a is less than b 0 otherwise.
	GT          = 0xA0 // Returns 1 if a is greater than b 0 otherwise.
	LTE         = 0xA1 // Returns 1 if a is less than or equal to b 0 otherwise.
	GTE         = 0xA2 // Returns 1 if a is greater than or equal to b 0 otherwise.
	MIN         = 0xA3 // Returns the smaller of a and b.
	MAX         = 0xA4 // Returns the larger of a and b.
	WITHIN      = 0xA5 // Returns 1 if x is within the specified range (left-inclusive) 0 otherwise.

	// Crypto
	//RIPEMD160  = 0xA6 // The input is hashed using RIPEMD-160.
	SHA1          = 0xA7 // The input is hashed using SHA-1.
	SHA256        = 0xA8 // The input is hashed using SHA-256.
	HASH160       = 0xA9
	HASH256       = 0xAA
	CHECKSIG      = 0xAC
	CHECKMULTISIG = 0xAE

	// Array
	ARRAYSIZE = 0xC0
	PACK      = 0xC1
	UNPACK    = 0xC2
	PICKITEM  = 0xC3
	SETITEM   = 0xC4
	NEWARRAY  = 0xC5 //用作引用類型
	NEWSTRUCT = 0xC6 //用作值類型
	APPEND    = 0xC8
	REVERSE   = 0xC9
	REMOVE    = 0xCA

	// Exceptions
	THROW      = 0xF0
	THROWIFNOT = 0xF1
)

// Script builder for script
type Script struct {
	script    string
	hash      string
	operation string
	args      []interface{}
}

func (script *Script) serielize(useTailCall bool) bool {
	for i := len(script.args) - 1; i >= 0; i-- {
		switch script.args[i].(type) {
		case float64:
			script.addFloat(script.args[i].(float64))
		case int:
			script.addInt(script.args[i].(int))
			break
		case string:
			script.addString(script.args[i].(string))
			break
		case bool:
			if script.args[i].(bool) {
				script.add(PUSHT, "")
			} else {
				script.add(PUSHF, "")
			}
			break
		default:
			return false
		}
	}
	script.addInt(len(script.args))
	script.add(PACK, "")

	// right here

	forOP := ""
	for i := 0; i < len(script.operation); i++ {
		forOP += utils.Int2Hex((int64)(script.operation[i]), 1, false)
	}
	script.addString(forOP)

	if useTailCall {
		script.add(TAILCALL, utils.ReverseHex(script.hash))
	} else {
		script.add(APPCALL, utils.ReverseHex(script.hash))
	}
	return true
}

// AddString add astring
func AddString(str string) (rs string) {
	size := len(str) / 2
	if size <= PUSHBYTES75 {
		rs += utils.Int2Hex((int64)(size), 1, false)
		rs += str
		return
	} else if size < 0x100 {
		rs += Add(PUSHDATA1, "")
		rs += utils.Int2Hex((int64)(size), 1, true)
		rs += str
		return
	} else if size < 0x10000 {
		rs += Add(PUSHDATA2, "")
		rs += utils.Int2Hex((int64)(size), 2, true)
		rs += str
		return
	} else { // if size < 0x100000000 {
		rs += Add(PUSHDATA4, "")
		rs += utils.Int2Hex((int64)(size), 4, true)
		rs += str
		return
	}
}

func (script *Script) addString(hex string) bool {
	size := len(hex) / 2
	if size <= PUSHBYTES75 {
		script.script += utils.Int2Hex((int64)(size), 1, false)
		script.script += hex
	} else if size < 0x100 {
		script.add(PUSHDATA1, "")
		script.script += utils.Int2Hex((int64)(size), 1, true)
		script.script += hex
	} else if size < 0x10000 {
		script.add(PUSHDATA2, "")
		script.script += utils.Int2Hex((int64)(size), 2, true)
		script.script += hex
	} else { // if size < 0x100000000 {
		script.add(PUSHDATA4, "")
		script.script += utils.Int2Hex((int64)(size), 4, true)
		script.script += hex
	}
	//  else {
	// 	return false
	// }
	return true
}

func (script *Script) addFloat(num float64) bool {
	script.addInt((int)(num * 100000000)) // fixed decimal
	return true
}

func (script *Script) addInt(num int) bool {
	if num == -1 {
		return script.add(PUSHM1, "")
	}
	if num == 0 {
		return script.add(PUSH0, "")
	}
	if num > 0 && num <= 16 {
		return script.add(PUSH1-1+num, "")
	}
	hexstring := utils.Int2HexInt((int64)(num))
	return script.addString(utils.ReverseHex(strings.Repeat("0", 16-len(hexstring)) + hexstring))
}

func (script *Script) add(op int, arg string) bool {
	script.script += utils.Int2Hex((int64)(op), 1, false)
	if len(arg) > 0 {
		script.script += arg
	}
	return true
}

// Add add param
func Add(op int64, arg string) string {
	rs := utils.Int2Hex((int64)(op), 1, false)
	if len(arg) > 0 {
		rs += arg
	}
	return rs
}
