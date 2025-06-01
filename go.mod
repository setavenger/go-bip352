module github.com/setavenger/go-bip352

go 1.23.1

toolchain go1.24.1

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.4
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/setavenger/go-libsecp256k1 v0.0.0
	github.com/stretchr/testify v1.8.0
	golang.org/x/crypto v0.17.0
)

require (
	github.com/btcsuite/btcd v0.23.5-0.20231215221805-96c9fd8078fd // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/setavenger/go-libsecp256k1 => ../go-libsecp256k1
