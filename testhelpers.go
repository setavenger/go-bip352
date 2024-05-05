package bip352

import (
	"encoding/json"
	"io/ioutil"
	"testing"
)

type VinReceiveTestCase struct {
	Txid        string `json:"txid"`
	Vout        uint32 `json:"vout"`
	ScriptSig   string `json:"scriptSig"`
	Txinwitness string `json:"txinwitness"`
	Prevout     struct {
		ScriptPubKey struct {
			Hex  string `json:"hex"`
			Type string `json:"type"`
		} `json:"scriptPubKey"`
	} `json:"prevout"`
}

type FullTestCase struct {
	Comment string `json:"comment"`
	Sending []struct {
		Given struct {
			Vin []struct {
				Txid        string `json:"txid"`
				Vout        uint32 `json:"vout"`
				ScriptSig   string `json:"scriptSig"`
				Txinwitness string `json:"txinwitness"`
				Prevout     struct {
					ScriptPubKey struct {
						Hex  string `json:"hex"`
						Type string `json:"type"`
					} `json:"scriptPubKey"`
				} `json:"prevout"`
				PrivateKey string `json:"private_key"`
			} `json:"vin"`
			Recipients []string `json:"recipients"`
		} `json:"given"`
		Expected struct {
			Outputs []string `json:"outputs"`
		} `json:"expected"`
	} `json:"sending"`
	Receiving []struct {
		Given struct {
			Vin         []VinReceiveTestCase `json:"vin"`
			Outputs     []string             `json:"outputs"`
			KeyMaterial struct {
				SpendPrivKey string `json:"spend_priv_key"`
				ScanPrivKey  string `json:"scan_priv_key"`
			} `json:"key_material"`
			Labels []uint32 `json:"labels"`
		} `json:"given"`
		Expected struct {
			Addresses []string `json:"addresses"`
			Outputs   []struct {
				PubKey       string `json:"pub_key"`
				PrivKeyTweak string `json:"priv_key_tweak"`
				Signature    string `json:"signature"`
			} `json:"outputs"`
			Tweak string `json:"tweak"`
		} `json:"expected"`
	} `json:"receiving"`
}

func LoadFullCaseData(t *testing.T) ([]FullTestCase, error) {
	filePath := "./test_data/send_and_receive_test_vectors_modified.json"

	// Read the JSON file
	data, err := ioutil.ReadFile(filePath)
	//if err != nil {
	//	t.Errorf("Error reading JSON file: %s", err)
	//	return nil, err
	//}

	// Assuming `testCases` is the variable for storing the unmarshaled data
	var testCases []FullTestCase

	// Unmarshal the JSON data into the struct
	err = json.Unmarshal(data, &testCases)
	//if err != nil {
	//	t.Errorf("Error unmarshaling JSON: %s", err)
	//	return nil, err
	//}

	return testCases, err
}
