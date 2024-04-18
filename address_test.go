package gobip352

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"reflect"
	"testing"
)

func TestFullAddressEncoding(t *testing.T) {
	caseData, err := LoadFullCaseData(t)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	for _, cases := range caseData {
		for _, testCase := range cases.Receiving {
			var containsMap = map[string]struct{}{}

			fmt.Println(cases.Comment)
			var spendSecKey []byte
			var scanSecKey []byte
			spendSecKey, err = hex.DecodeString(testCase.Given.KeyMaterial.SpendPrivKey)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}

			scanSecKey, err = hex.DecodeString(testCase.Given.KeyMaterial.ScanPrivKey)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}
			_, scanPubKey := btcec.PrivKeyFromBytes(scanSecKey)
			_, spendPubKey := btcec.PrivKeyFromBytes(spendSecKey)

			scanPubKeyBytes := scanPubKey.SerializeCompressed()
			spendPubKeyBytes := spendPubKey.SerializeCompressed()

			var address = ""
			address, err = CreateAddress(scanPubKeyBytes, spendPubKeyBytes, true, 0)
			if err != nil {
				t.Errorf("Error: %s", err)
				return
			}

			containsMap[address] = struct{}{}
			for _, label := range testCase.Given.Labels {
				var labeledAddress string
				labeledAddress, err = CreateLabeledAddress(scanPubKeyBytes, spendPubKeyBytes, true, 0, scanSecKey, label)
				if err != nil {
					t.Errorf("Error: %s", err)
					return
				}
				containsMap[labeledAddress] = struct{}{}
			}

			for _, targetAddress := range testCase.Expected.Addresses {
				_, exists := containsMap[targetAddress]
				if !exists {
					t.Errorf("Error: missing %s", targetAddress)
					return
				}
			}
		}

	}
}

func TestDecodeSPAddress(t *testing.T) {
	decodedData, _ := hex.DecodeString("0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36")
	address := "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
	hrp, data, version, err := DecodeSilentPaymentAddress(address, true)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	if hrp != "sp" {
		t.Errorf("Error: wrong hrp %s != sp", hrp)
		return
	}

	if !reflect.DeepEqual(decodedData, data) {
		t.Errorf("Error: data not decoded correctly")
		return
	}
	if version != 0 {
		t.Errorf("Error: wrong version %d != 0", version)
		return
	}
}

func TestDecodeSPAddressToKeys(t *testing.T) {
	scanPubKeyBytesCheck, _ := hex.DecodeString("0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4")
	spendPubKeyBytesCheck, _ := hex.DecodeString("025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36")
	address := "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
	scanPubKeyBytes, spendPubKeyBytes, err := DecodeSilentPaymentAddressToKeys(address, true)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	if !reflect.DeepEqual(scanPubKeyBytesCheck, scanPubKeyBytes) {
		t.Errorf("Error: wrong scan key %x != %x", scanPubKeyBytes, scanPubKeyBytesCheck)
		return
	}
	if !reflect.DeepEqual(spendPubKeyBytesCheck, spendPubKeyBytes) {
		t.Errorf("Error: wrong scan key %x != %x", spendPubKeyBytes, spendPubKeyBytesCheck)
		return
	}
}
