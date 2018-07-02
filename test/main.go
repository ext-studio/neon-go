package main

import (
	"fmt"

	"../libs/transaction"
	"../libs/utils"
	"../libs/wallet"
)

func main() {
	fmt.Println(transaction.Transaction())
	fmt.Println(utils.Utils())
	fmt.Println(wallet.Wallet())
}
