# neon-go

neo thin wallet utils in golang

## Modules include

### Wallet

1. private key generation
2. parse from/to WIF/Address/PublicKey/ScriptHash
3. NEP-2 support

### Transaction

completing

## Compile for Android

```
gomobile bind -target=android -o="dist/android/neon-go.aar" -javapkg="com.yitimo.neon" github.com/yitimo/neon-go/libs/wallet github.com/yitimo/neon-go/libs/crypto github.com/yitimo/neon-go/libs/models github.com/yitimo/neon-go/libs/transaction github.com/yitimo/neon-go/libs/utils
```