package gobip352

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type Vin struct {
	Txid         [32]byte  // txid has to be in the normal human-readable format
	Vout         uint32    // output index of the input
	Amount       uint64    // value of the utxo in satoshi (100_000_000 sat = 1 Bitcoin)
	PublicKey    *[33]byte // 33 byte compressed public key or 32 byte taproot x-only key
	SecretKey    *[32]byte // 32 byte secret key
	Taproot      bool      // indicates whether input is taproot or not. taproot outputs have to be even hence the flag has to be set, so we can check for negation
	Witness      [][]byte  // witness data for the input
	ScriptPubKey []byte    // the scriptPubKey of the input
	ScriptSig    []byte    // used for p2pkh
}

func (v Vin) Hash() *chainhash.Hash {
	hash, err := chainhash.NewHash(v.Txid[:])
	if err != nil {
		panic(err)
	}
	return hash
}

func (v Vin) Index() uint32 {
	return v.Vout
}

func (v Vin) Value() btcutil.Amount {
	return btcutil.Amount(v.Amount)
}

func (v Vin) PkScript() []byte {
	return v.ScriptPubKey
}

// NumConfs not implemented
func (v Vin) NumConfs() int64 {
	return 0
}

// ValueAge not implemented
func (v Vin) ValueAge() int64 {
	return 0
}
