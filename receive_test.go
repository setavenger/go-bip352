package gobip352

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"testing"
)

func TestReceiverScanTransaction(t *testing.T) {

	caseData, err := LoadFullCaseData(t)
	if err != nil {
		return
	}

	for i, cases := range caseData {
		//if cases.Comment != "Single recipient: taproot input with NUMS point" {
		//	continue
		//}
		for _, testCase := range cases.Receiving {
			fmt.Println(i, cases.Comment)

			// extract privateKeys
			var secKeyScanBytes []byte
			secKeyScanBytes, err = hex.DecodeString(testCase.Given.KeyMaterial.ScanPrivKey)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}
			secKeyScan := ConvertToFixedLength32(secKeyScanBytes)
			// extract keys
			var secKeySpendBytes []byte
			secKeySpendBytes, err = hex.DecodeString(testCase.Given.KeyMaterial.SpendPrivKey)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}
			secKeySpend := ConvertToFixedLength32(secKeySpendBytes)
			_, scanPubKey := btcec.PrivKeyFromBytes(secKeyScan[:])
			_, spendPubKey := btcec.PrivKeyFromBytes(secKeySpend[:])

			// compute label data
			var labels []Label
			for _, labelInt := range testCase.Given.Labels {
				var label Label
				label, err = CreateLabel(secKeyScan, labelInt)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}

				var labeledAddress string
				// todo not happy with this API yet should be able to create an address without introducing the secretKey again
				labeledAddress, err = CreateLabeledAddress(
					ConvertToFixedLength33(scanPubKey.SerializeCompressed()),
					ConvertToFixedLength33(spendPubKey.SerializeCompressed()),
					true,
					0,
					secKeyScan,
					labelInt,
				)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}

				label.Address = labeledAddress

				labels = append(labels, label)
			}

			// check the generated addresses
			containsMap := make(map[string]struct{})
			var address string
			address, err = CreateAddress(
				ConvertToFixedLength33(scanPubKey.SerializeCompressed()),
				ConvertToFixedLength33(spendPubKey.SerializeCompressed()),
				true,
				0,
			)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}

			containsMap[address] = struct{}{}

			for _, label := range labels {
				containsMap[label.Address] = struct{}{}
			}

			for _, targetAddress := range testCase.Expected.Addresses {
				_, exists := containsMap[targetAddress]
				if !exists {
					t.Errorf("Error: missing %s", targetAddress)
					return
				}
			}

			// get the txOutputs of the transactions
			var txOutputs [][32]byte
			for _, output := range testCase.Given.Outputs {
				var decodedString []byte
				decodedString, err = hex.DecodeString(output)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}
				txOutputs = append(txOutputs, ConvertToFixedLength32(decodedString))
			}

			// compute tweak data
			var publicComponent [33]byte
			var inputHash [32]byte
			publicComponent, inputHash, err = ExtractTweak(testCase.Given.Vin)
			if err != nil && !errors.Is(err, noErrJustSkip) {
				t.Errorf("Error: %s", err)
				return
			} else if err != nil && errors.Is(err, noErrJustSkip) {
				t.Log("we skipped")
				continue
			}

			var foundOutputs []*FoundOutput
			foundOutputs, err = ReceiverScanTransaction(
				secKeyScan,
				ConvertToFixedLength33(spendPubKey.SerializeCompressed()),
				labels,
				txOutputs,
				publicComponent,
				&inputHash,
			)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}

			if len(foundOutputs) != len(testCase.Expected.Outputs) {
				t.Errorf("Error: wrong number outputs found %d != %d", len(foundOutputs), len(testCase.Expected.Outputs))
				return
			}

			// todo come up with test to check for labels properly found and added to foundOutput
			for i2, foundOutput := range foundOutputs {
				targetPubKey, _ := hex.DecodeString(testCase.Expected.Outputs[i2].PubKey)
				targetPrivKeyTweak, _ := hex.DecodeString(testCase.Expected.Outputs[i2].PrivKeyTweak)
				if !bytes.Equal(foundOutput.Output[:], targetPubKey) {
					t.Errorf("Error: output not matched %x != %x", foundOutput.Output, targetPubKey)
					return
				}
				if !bytes.Equal(foundOutput.SecKeyTweak[:], targetPrivKeyTweak) {
					t.Errorf("Error: output not matched %x != %x", foundOutput.Output, targetPubKey)
					return
				}

				// check signatures
				// Message and auxiliary data
				message := []byte("message")
				aux := []byte("random auxiliary data")

				// Hashing message and auxiliary data
				msgHash := sha256.Sum256(message)
				auxHash := sha256.Sum256(aux)

				fullPrivKeyBytes := AddPrivateKeys(secKeySpend, foundOutput.SecKeyTweak)
				fullPrivKey, _ := btcec.PrivKeyFromBytes(fullPrivKeyBytes[:])

				// Sign the message with auxiliary data influencing the nonce
				var signature *schnorr.Signature
				signature, err = schnorr.Sign(fullPrivKey, msgHash[:], schnorr.CustomNonce(auxHash))
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}
				var parsedOutput *btcec.PublicKey
				parsedOutput, err = btcec.ParsePubKey(append([]byte{0x02}, foundOutput.Output[:]...))
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}
				valid := signature.Verify(msgHash[:], parsedOutput)
				if !valid {
					t.Errorf("Error: signature was not valid")
					return
				}
			}
		}
	}
}

func ExtractTweak(caseDataVins []VinReceiveTestCase) ([33]byte, [32]byte, error) {
	// convert the test vins into proper vins

	var pubKeys [][33]byte
	var vins []*Vin

	for _, vin := range caseDataVins {
		txid, _ := hex.DecodeString(vin.Txid)
		scriptSig, _ := hex.DecodeString(vin.ScriptSig)
		scriptPubKey, _ := hex.DecodeString(vin.Prevout.ScriptPubKey.Hex)
		witness, _ := hex.DecodeString(vin.Txinwitness)
		var witnessScript [][]byte
		if len(witness) > 0 {
			var err error
			witnessScript, err = ParseWitnessScript(witness)
			if err != nil {
				return [33]byte{}, [32]byte{}, err
			}
		}

		vinInner := &Vin{
			Txid:         ConvertToFixedLength32(txid),
			Vout:         vin.Vout,
			Witness:      witnessScript,
			ScriptPubKey: scriptPubKey,
			ScriptSig:    scriptSig,
		}

		vins = append(vins, vinInner)

		pubKey, utxoType, err := extractPubKey(vinInner)
		if err != nil {
			return [33]byte{}, [32]byte{}, err
		}

		// skip in case no pub key was extracted and no error was thrown
		if pubKey == nil {
			continue
		}

		if utxoType == P2TR {
			pubKey = append([]byte{0x02}, pubKey...)
		}

		pubKeys = append(pubKeys, ConvertToFixedLength33(pubKey))
	}

	if len(pubKeys) == 0 {
		return [33]byte{}, [32]byte{}, noErrJustSkip
	}

	sumPublicKeys, err := SumPublicKeys(pubKeys)
	if err != nil {
		return [33]byte{}, [32]byte{}, err
	}

	// compute inputHash
	inputHash, err := ComputeInputHash(vins, sumPublicKeys)
	if err != nil {
		return [33]byte{}, [32]byte{}, err
	}

	return sumPublicKeys, inputHash, err
}
