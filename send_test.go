package bip352

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func TestSenderCreateOutputs(t *testing.T) {
	caseData, err := LoadFullCaseData(t)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	for i, cases := range caseData {
		if cases.Comment == "Single recipient: taproot input with NUMS point" ||
			cases.Comment == "P2PKH and P2WPKH Uncompressed Keys are skipped" ||
			cases.Comment == "Skip invalid P2SH inputs" ||
			cases.Comment == "No valid inputs, sender generates no outputs" {
			// This library does not focus on extracting the correct public keys from an input.
			// This feature might be added in future versions but as of now this will be skipped.
			// The focus is to provide the basic wrapper around the EC computations and other lower level computations.
			// Check the BIP352 reference implementation or https://github.com/setavenger/BlindBit-Backend/blob/61a47e5c657bd48c55ac6acec91e0a26d115e7f2/src/core/tweak.go#L307
			// to see how sanitizing the inputs could be attempted
			// todo add module to sanitize
			continue
		}
		for _, testCase := range cases.Sending {
			fmt.Println(i, cases.Comment)

			var vins []*Vin
			var recipients []*Recipient

			for _, vin := range testCase.Given.Vin {
				var txid []byte
				var secKey []byte

				txid, err = hex.DecodeString(vin.Txid)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}

				secKey, err = hex.DecodeString(vin.PrivateKey)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}

				var scriptPubKey []byte
				scriptPubKey, err = hex.DecodeString(vin.Prevout.ScriptPubKey.Hex)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}

				interimSecKey := ConvertToFixedLength32(secKey)

				vins = append(vins, &Vin{
					Txid:      ConvertToFixedLength32(txid),
					Vout:      vin.Vout,
					PublicKey: nil,
					SecretKey: &interimSecKey,
					Taproot:   isP2TR(scriptPubKey),
				})
			}

			for _, recipient := range testCase.Given.Recipients {
				recipients = append(recipients, &Recipient{
					SilentPaymentAddress: recipient,
				})
			}

			err = SenderCreateOutputs(recipients, vins, true, false)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}

			var containsMap = map[string]struct{}{}
			for _, recipient := range recipients {
				//t.Logf("B_scan: %x", recipient.ScanPubKey.SerializeCompressed())
				containsMap[hex.EncodeToString(recipient.Output[:])] = struct{}{}
			}

			foundCounter := 0
			for _, targetOutput := range testCase.Expected.Outputs {
				_, exists := containsMap[targetOutput]
				if exists {
					foundCounter++
				}
			}
			if foundCounter != len(recipients) {
				t.Errorf("Error: did not find enough correct outputs")
				t.Errorf("Error: Found %d expected %d", foundCounter, len(recipients))
				return
			}
		}
	}
}

func TestSenderCreateOutputsWithVinCheck(t *testing.T) {
	caseData, err := LoadFullCaseData(t)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	for i, cases := range caseData {
		fmt.Println(i, cases.Comment)

		for _, testCase := range cases.Sending {

			var vins []*Vin
			var recipients []*Recipient

			for _, vin := range testCase.Given.Vin {
				var txid []byte
				var secKey []byte

				txid, err = hex.DecodeString(vin.Txid)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}

				secKey, err = hex.DecodeString(vin.PrivateKey)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}

				var scriptPubKey []byte
				scriptPubKey, err = hex.DecodeString(vin.Prevout.ScriptPubKey.Hex)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}
				var scriptSig []byte
				scriptSig, err = hex.DecodeString(vin.ScriptSig)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}

				witness, _ := hex.DecodeString(vin.Txinwitness)
				var witnessScript [][]byte
				if len(witness) > 0 {
					witnessScript, err = ParseWitnessScript(witness)
					if err != nil {
						t.Errorf("Error: %s", err)
						return
					}
				}

				interimSecKey := ConvertToFixedLength32(secKey)

				vins = append(vins, &Vin{
					Txid:         ConvertToFixedLength32(txid),
					Vout:         vin.Vout,
					PublicKey:    nil,
					ScriptPubKey: scriptPubKey,
					ScriptSig:    scriptSig,
					Witness:      witnessScript,
					SecretKey:    &interimSecKey,
					Taproot:      isP2TR(scriptPubKey),
				})
			}

			for _, recipient := range testCase.Given.Recipients {
				recipients = append(recipients, &Recipient{
					SilentPaymentAddress: recipient,
				})
			}

			err = SenderCreateOutputs(recipients, vins, true, true)
			if err != nil {
				if cases.Comment == "No valid inputs, sender generates no outputs" && errors.Is(err, ErrNoEligibleVins) {
					continue
				}
				t.Errorf("Error: %s", err)
				return
			}

			var containsMap = map[string]struct{}{}
			for _, recipient := range recipients {
				//t.Logf("B_scan: %x", recipient.ScanPubKey.SerializeCompressed())
				containsMap[hex.EncodeToString(recipient.Output[:])] = struct{}{}
			}

			foundCounter := 0
			for _, targetOutput := range testCase.Expected.Outputs {
				_, exists := containsMap[targetOutput]
				if exists {
					foundCounter++
				}
			}
			if foundCounter != len(recipients) {
				t.Errorf("Error: did not find enough correct outputs")
				t.Errorf("Error: Found %d expected %d", foundCounter, len(recipients))
				return
			}
		}
	}
}

// todo write test to check that stored data in recipient stays there
