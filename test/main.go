package main

import (
	"fmt"

	"github.com/yitimo/neon-go"
	"github.com/yitimo/neon-go/libs/wallet"
)

func main() {
	wallet.Wallet()
	fmt.Println(neon.Transaction())
	fmt.Println(neon.Utils())
	fmt.Println(neon.Wallet())
}
