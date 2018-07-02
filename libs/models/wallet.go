package models

type Scrypt struct {
	N int64
	R int64
	P int64
}

type ContractParameter struct {
	Name string
	Type string
}

type Contract struct {
	Script     string
	Parameters []ContractParameter
	Deployed   bool
}

type Account struct {
	Address   string
	Label     []string
	IsDefault bool
	Lock      bool
	Key       string
	Contract  Contract
	Extra     string
}

type Wallet struct {
	Name     string
	Version  string
	Scrypt   Scrypt
	Accounts []Account
	Extra    string
}
