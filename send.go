package gobip352

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
)

type Recipient struct {
	SilentPaymentAddress string
	ScanPubKey           *btcec.PublicKey
	SpendPubKey          *btcec.PublicKey
	Output               []byte         // the resulting taproot x-only output
	Index                uint           // todo might be removed
	Data                 map[string]any // in order to allocate data to a recipient that needs to be known after handling
}

type Vin struct {
	Txid      []byte // txid has to be in the normal human-readable format
	Vout      uint32
	PublicKey []byte // 33 byte compressed public key or 32 byte taproot x-only key
	SecretKey []byte // 32 byte secret key
	Taproot   bool   // taproot outputs have to be even hence the flag has to be set, so we can check for negation
}

/*
SenderCreateOutputs
recipients: must include result will be stored in the recipients.
vins: has to include the txids and vouts
*/
func SenderCreateOutputs(recipients []*Recipient, vins []*Vin, mainnet bool) error {
	var secretKeys [][]byte

	// negate keys if necessary before summing them
	for _, vin := range vins {
		var secKey = vin.SecretKey
		fmt.Printf("secKey: %x\n", secKey)

		if vin.Taproot {
			secKey = checkToNegate(vin.SecretKey)
		}

		fmt.Printf("secKey: %x\n", secKey)
		secretKeys = append(secretKeys, secKey)
	}

	// sum up the privateKeys
	secKeySum := RecursiveAddPrivateKeys(secretKeys)

	// derive A_sum from the private key sum aG + bG = [a+b]*G
	_, publicKeySum := btcec.PrivKeyFromBytes(secKeySum)

	publicKeySumBytes := publicKeySum.SerializeCompressed()

	// compute inputHash
	inputHash, err := ComputeInputHash(vins, publicKeySumBytes)
	if err != nil {
		return err
	}

	// extract the pubKeys from the SP address
	for _, recipient := range recipients {
		scanPubKeyBytes, spendPubKeyBytes, err := DecodeSilentPaymentAddressToKeys(recipient.SilentPaymentAddress, mainnet)
		scanPubKey, err := btcec.ParsePubKey(scanPubKeyBytes)
		if err != nil {
			return err
		}
		spendPubKey, err := btcec.ParsePubKey(spendPubKeyBytes)
		if err != nil {
			return err
		}

		recipient.ScanPubKey, recipient.SpendPubKey = scanPubKey, spendPubKey
	}

	groups := matchRecipients(recipients)

	for scanKey, groupRecipients := range groups {
		scanKeyBytes, err := hex.DecodeString(scanKey)
		if err != nil {
			return err
		}
		sharedSecret, err := CreateSharedSecret(scanKeyBytes, secKeySum, inputHash)
		if err != nil {
			return err
		}

		var k uint32 = 0
		for _, recipient := range groupRecipients {
			outputPubKey, err := CreateOutputPubKey(sharedSecret, recipient.SpendPubKey.SerializeCompressed(), k)
			if err != nil {
				return err
			}
			recipient.Output = outputPubKey
			k++
		}
	}

	return nil
}

func checkToNegate(secretKey []byte) []byte {
	sk, pk := btcec.PrivKeyFromBytes(secretKey)
	if pk.Y().Bit(0) != 0 {
		// now we have to negate the secretKey
		secretKeyArr := sk.Key.Negate().Bytes()
		return secretKeyArr[:]
	} else {
		return secretKey
	}
}

func matchRecipients(recipients []*Recipient) map[string][]*Recipient {
	matches := make(map[string][]*Recipient)

	for _, recipient := range recipients {
		scanKey := hex.EncodeToString(recipient.ScanPubKey.SerializeCompressed())
		matches[scanKey] = append(matches[scanKey], recipient)
	}

	return matches
}

// recipient
