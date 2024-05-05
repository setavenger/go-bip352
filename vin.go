package bip352

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
		// panic it should never ever panic but if for god knows what this fails we want to panic early and not get zero slices or anything somewhere
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

func (v *Vin) DeepCopy() *Vin {
	if v == nil {
		return nil
	}

	copyVin := Vin{
		Txid:    v.Txid, // directly copied as it is an array
		Vout:    v.Vout,
		Amount:  v.Amount,
		Taproot: v.Taproot,
	}

	// Copy PublicKey
	if v.PublicKey != nil {
		copyPublicKey := *v.PublicKey
		copyVin.PublicKey = &copyPublicKey
	}

	// Copy SecretKey
	if v.SecretKey != nil {
		copySecretKey := *v.SecretKey
		copyVin.SecretKey = &copySecretKey
	}

	// Deep copy Witness
	if v.Witness != nil {
		copyVin.Witness = make([][]byte, len(v.Witness))
		for i, data := range v.Witness {
			copyVin.Witness[i] = make([]byte, len(data))
			copy(copyVin.Witness[i], data)
		}
	}

	// Deep copy ScriptPubKey
	if v.ScriptPubKey != nil {
		copyVin.ScriptPubKey = make([]byte, len(v.ScriptPubKey))
		copy(copyVin.ScriptPubKey, v.ScriptPubKey)
	}

	// Deep copy ScriptSig
	if v.ScriptSig != nil {
		copyVin.ScriptSig = make([]byte, len(v.ScriptSig))
		copy(copyVin.ScriptSig, v.ScriptSig)
	}

	return &copyVin
}
