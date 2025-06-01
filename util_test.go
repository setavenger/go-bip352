package bip352

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/setavenger/blindbit-lib/utils"
)

func TestRecursiveAddPrivateKeys(t *testing.T) {
	secKey1, _ := hex.DecodeString("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1")
	secKey2, _ := hex.DecodeString("fc8716a97a48ba9a05a98ae47b5cd201a25a7fd5d8b73c203c5f7b6b6b3b6ad7")
	secKey3, _ := hex.DecodeString("1d37787c2b7116ee983e9f9c13269df29091b391c04db94239e0d2bc2182c3bf")

	pKey1, _ := hex.DecodeString("025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5")
	pKey2, _ := hex.DecodeString("02782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338")
	pKey3, _ := hex.DecodeString("038c8d23d4764feffcd5e72e380802540fa0f88e3d62ad5e0b47955f74d7b283c4")

	testRecursiveHelper(t, [][32]byte{
		utils.ConvertToFixedLength32(secKey1),
	}, [][33]byte{
		utils.ConvertToFixedLength33(pKey1),
	})
	testRecursiveHelper(t, [][32]byte{
		utils.ConvertToFixedLength32(secKey1),
		utils.ConvertToFixedLength32(secKey2),
	}, [][33]byte{
		utils.ConvertToFixedLength33(pKey1),
		utils.ConvertToFixedLength33(pKey2),
	})
	testRecursiveHelper(t, [][32]byte{
		utils.ConvertToFixedLength32(secKey1),
		utils.ConvertToFixedLength32(secKey2),
		utils.ConvertToFixedLength32(secKey3),
	}, [][33]byte{
		utils.ConvertToFixedLength33(pKey1),
		utils.ConvertToFixedLength33(pKey2),
		utils.ConvertToFixedLength33(pKey3),
	})
}

func testRecursiveHelper(t *testing.T, secKeys [][32]byte, pKeys [][33]byte) {
	secKeysSum := RecursiveAddPrivateKeys(secKeys)

	pKeysSum, err := SumPublicKeys(pKeys)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	_, pKeyFromSecSum := btcec.PrivKeyFromBytes(secKeysSum[:])

	if !bytes.Equal(pKeysSum[:], pKeyFromSecSum.SerializeCompressed()) {
		t.Errorf("Error: secKey: %x", secKeysSum)
		t.Errorf("Error: %x != %x", pKeysSum, pKeyFromSecSum.SerializeCompressed())
		return
	}
}
