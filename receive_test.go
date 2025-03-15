package bip352

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func TestReceiverScanTransaction(t *testing.T) {
	caseData, err := LoadFullCaseData(t)
	if err != nil {
		return
	}

	for iOuter, cases := range caseData {
		// for _, cases := range caseData {
		for _, testCase := range cases.Receiving {
			fmt.Println(iOuter, cases.Comment)

			// extract privateKeys
			var secKeyScanBytes []byte
			secKeyScanBytes, err = hex.DecodeString(testCase.Given.KeyMaterial.ScanPrivKey)
			require.NoError(t, err)

			secKeyScan := ConvertToFixedLength32(secKeyScanBytes)
			// extract keys
			var secKeySpendBytes []byte
			secKeySpendBytes, err = hex.DecodeString(testCase.Given.KeyMaterial.SpendPrivKey)
			require.NoError(t, err)

			secKeySpend := ConvertToFixedLength32(secKeySpendBytes)
			_, scanPubKey := btcec.PrivKeyFromBytes(secKeyScan[:])
			_, spendPubKey := btcec.PrivKeyFromBytes(secKeySpend[:])

			// compute label data
			var labels []*Label
			for _, labelInt := range testCase.Given.Labels {
				var label Label
				label, err = CreateLabel(secKeyScan, labelInt)
				require.NoError(t, err)

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
				require.NoError(t, err)

				label.Address = labeledAddress

				labels = append(labels, &label)
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
			require.NoError(t, err)

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
				require.NoError(t, err)

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
				fmt.Println("we skipped")
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
			require.NoError(t, err)

			if len(foundOutputs) != len(testCase.Expected.Outputs) {
				t.Errorf("Error: wrong number outputs found %d != %d", len(foundOutputs), len(testCase.Expected.Outputs))
				return
			}

			// todo come up with test to check for labels properly found and added to foundOutput
			for iInner, foundOutput := range foundOutputs {
				targetPubKey, _ := hex.DecodeString(testCase.Expected.Outputs[iInner].PubKey)
				targetPrivKeyTweak, _ := hex.DecodeString(testCase.Expected.Outputs[iInner].PrivKeyTweak)
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

				var fullKeyBytes [32]byte
				copy(fullKeyBytes[:], secKeySpend[:])

				err := AddPrivateKeys(&fullKeyBytes, &foundOutput.SecKeyTweak)
				require.NoError(t, err)
				fullPrivKey, _ := btcec.PrivKeyFromBytes(fullKeyBytes[:])

				// Sign the message with auxiliary data influencing the nonce
				var signature *schnorr.Signature
				signature, err = schnorr.Sign(fullPrivKey, msgHash[:], schnorr.CustomNonce(auxHash))
				require.NoError(t, err)

				var parsedOutput *btcec.PublicKey
				parsedOutput, err = btcec.ParsePubKey(append([]byte{0x02}, foundOutput.Output[:]...))
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}
				valid := signature.Verify(msgHash[:], parsedOutput)
				if !valid {
					fmt.Printf("%d %x\n", iInner, foundOutput.Output)
					fmt.Printf("%d %x\n", iInner, foundOutput.SecKeyTweak)
					panic("error")
					t.Errorf("Error: signature was not valid")
					return
				}
			}
		}
	}
}

func BenchmarkReceiverScanTransaction(b *testing.B) {
	caseData, err := LoadFullCaseData(b)
	require.NoError(b, err)

	iOuter := 17
	cases := caseData[iOuter]
	testCase := cases.Receiving[0]

	fmt.Println(iOuter, cases.Comment)

	// extract privateKeys
	var secKeyScanBytes []byte
	secKeyScanBytes, err = hex.DecodeString(testCase.Given.KeyMaterial.ScanPrivKey)
	require.NoError(b, err)

	secKeyScan := ConvertToFixedLength32(secKeyScanBytes)
	// extract keys
	var secKeySpendBytes []byte
	secKeySpendBytes, err = hex.DecodeString(testCase.Given.KeyMaterial.SpendPrivKey)
	require.NoError(b, err)

	secKeySpend := ConvertToFixedLength32(secKeySpendBytes)
	_, scanPubKey := btcec.PrivKeyFromBytes(secKeyScan[:])
	_, spendPubKey := btcec.PrivKeyFromBytes(secKeySpend[:])

	// compute label data
	var labels []*Label
	for _, labelInt := range testCase.Given.Labels {
		var label Label
		label, err = CreateLabel(secKeyScan, labelInt)
		require.NoError(b, err)

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
		require.NoError(b, err)

		label.Address = labeledAddress

		labels = append(labels, &label)
	}
	//
	// // check the generated addresses
	// containsMap := make(map[string]struct{})
	// var address string
	// address, err = CreateAddress(
	// 	ConvertToFixedLength33(scanPubKey.SerializeCompressed()),
	// 	ConvertToFixedLength33(spendPubKey.SerializeCompressed()),
	// 	true,
	// 	0,
	// )
	// if err != nil {
	// 	b.Errorf("Error: %s", err)
	// 	return
	// }

	// containsMap[address] = struct{}{}
	//
	// for _, label := range labels {
	// 	containsMap[label.Address] = struct{}{}
	// }
	//
	// for _, targetAddress := range testCase.Expected.Addresses {
	// 	_, exists := containsMap[targetAddress]
	// 	if !exists {
	// 		b.Errorf("Error: missing %s", targetAddress)
	// 		return
	// 	}
	// }

	// get the txOutputs of the transactions
	var txOutputs [][32]byte
	for _, output := range testCase.Given.Outputs {
		var decodedString []byte
		decodedString, err = hex.DecodeString(output)
		require.NoError(b, err)

		txOutputs = append(txOutputs, ConvertToFixedLength32(decodedString))
	}

	// compute tweak data
	var publicComponent [33]byte
	var inputHash [32]byte
	publicComponent, inputHash, err = ExtractTweak(testCase.Given.Vin)
	if err != nil && !errors.Is(err, noErrJustSkip) {
		b.Errorf("Error: %s", err)
		return
	} else if err != nil && errors.Is(err, noErrJustSkip) {
		b.Log("we skipped")
		return
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = ReceiverScanTransaction(
			secKeyScan,
			ConvertToFixedLength33(spendPubKey.SerializeCompressed()),
			labels,
			txOutputs,
			publicComponent,
			&inputHash,
		)
	}
}

// ExtractTweak
// returns: publicComponent, inputHash, error
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

		pubKey, utxoType := ExtractPubKey(vinInner)
		if utxoType == Unknown {
			continue
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
