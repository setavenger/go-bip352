package bip352

import (
	"bytes"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcutil"
	"testing"
)

func TestVin(t *testing.T) {
	txid, _ := hex.DecodeString("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
	pkScript, _ := hex.DecodeString("5120f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
	var vout uint32 = 3

	var targetAmount uint64 = 10_000_000

	var vin = Vin{
		Txid:         ConvertToFixedLength32(txid),
		Vout:         vout,
		ScriptPubKey: pkScript,
		Amount:       targetAmount,
	}

	if !bytes.Equal(vin.Hash()[:], txid) {
		t.Errorf("Error: txid hashes don't match")
		return
	}

	if !bytes.Equal(vin.PkScript(), pkScript) {
		t.Errorf("Error: scriptPubKeys don't match")
		return
	}

	if vin.Index() != vout {
		t.Errorf("Error: vouts don't match")
		return
	}

	if vin.Value() != btcutil.Amount(targetAmount) {
		t.Errorf("Error: amounts don't match")
		return
	}

	if vin.NumConfs() != 0 {
		t.Errorf("Error: wrong numConfs returned")
		return
	}

	if vin.ValueAge() != 0 {
		t.Errorf("Error: wrong valueAge returned")
		return
	}
}
