package gobip352

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
		if cases.Comment != "Receiving with labels: label with odd parity" {
			continue
		}
		for _, testCase := range cases.Receiving {
			fmt.Println(i, cases.Comment)

			// extract privateKeys
			var secKeyScan []byte
			secKeyScan, err = hex.DecodeString(testCase.Given.KeyMaterial.ScanPrivKey)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}
			// extract keys
			var secKeySpend []byte
			secKeySpend, err = hex.DecodeString(testCase.Given.KeyMaterial.SpendPrivKey)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}
			_, scanPubKey := btcec.PrivKeyFromBytes(secKeyScan)
			_, spendPubKey := btcec.PrivKeyFromBytes(secKeySpend)

			// compute label data
			var labels []Label
			for _, labelInt := range testCase.Given.Labels {
				var label Label
				label, err = CreateLabel(secKeyScan, labelInt)
				if err != nil {
					t.Errorf("Error: %s", err)
				}

				var labeledAddress string
				// todo not happy with this API yet should be able to create an address without introducing the secretKey again
				labeledAddress, err = CreateLabeledAddress(scanPubKey.SerializeCompressed(), spendPubKey.SerializeCompressed(), true, 0, secKeyScan, labelInt)
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
			address, err = CreateAddress(scanPubKey.SerializeCompressed(), spendPubKey.SerializeCompressed(), true, 0)
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
			var txOutputs [][]byte
			for _, output := range testCase.Given.Outputs {
				var decodedString []byte
				decodedString, err = hex.DecodeString(output)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}
				txOutputs = append(txOutputs, decodedString)
			}

			// compute tweak data
			var publicComponent []byte
			var inputHash []byte
			publicComponent, inputHash, err = ExtractTweak(testCase.Given.Vin)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}

			var foundOutputs []*FoundOutputs
			foundOutputs, err = ReceiverScanTransaction(secKeyScan, spendPubKey.SerializeCompressed(), labels, txOutputs, publicComponent, inputHash)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}

			for i2, foundOutput := range foundOutputs {
				targetPubKey, _ := hex.DecodeString(testCase.Expected.Outputs[i2].PubKey)
				targetPrivKeyTweak, _ := hex.DecodeString(testCase.Expected.Outputs[i2].PrivKeyTweak)
				if !bytes.Equal(foundOutput.Output, targetPubKey) {
					t.Errorf("Error: output not matched %x != %x", foundOutput.Output, targetPubKey)
					return
				}
				if !bytes.Equal(foundOutput.SecKeyTweak, targetPrivKeyTweak) {
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

				fullPrivKey, _ := btcec.PrivKeyFromBytes(AddPrivateKeys(secKeySpend, foundOutput.SecKeyTweak))

				// Sign the message with auxiliary data influencing the nonce
				var signature *schnorr.Signature
				signature, err = schnorr.Sign(fullPrivKey, msgHash[:], schnorr.CustomNonce(auxHash))
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}
				var parsedOutput *btcec.PublicKey
				parsedOutput, err = btcec.ParsePubKey(append([]byte{0x02}, foundOutput.Output...))
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

func ExtractTweak(caseDataVins []VinReceiveTestCase) ([]byte, []byte, error) {
	// convert the test vins into proper vins

	var pubKeys [][]byte
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
				return nil, nil, err
			}
		}

		vinInner := &Vin{
			Txid:         txid,
			Vout:         vin.Vout,
			PublicKey:    nil,
			SecretKey:    nil,
			Taproot:      false,
			Witness:      witnessScript,
			ScriptPubKey: scriptPubKey,
			ScriptSig:    scriptSig,
		}

		vins = append(vins, vinInner)

		pubKey, _, err := extractPubKey(vinInner)

		if err != nil {
			return nil, nil, err
		}

		pubKeys = append(pubKeys, pubKey)
	}

	sumPublicKeys, err := SumPublicKeys(pubKeys)
	if err != nil {
		return nil, nil, err
	}

	// compute inputHash
	inputHash, err := ComputeInputHash(vins, sumPublicKeys)
	if err != nil {
		return nil, nil, err
	}

	return sumPublicKeys, inputHash, err
}
