package gobip352

import (
	"github.com/btcsuite/btcd/btcec/v2"
)

type Recipient struct {
	SilentPaymentAddress string
	ScanPubKey           *btcec.PublicKey
	SpendPubKey          *btcec.PublicKey
	Output               [32]byte // the resulting taproot x-only output
	Amount               uint64
	Data                 map[string]any // in order to allocate data to a recipient that needs to be known after handling
}

/*
SenderCreateOutputs
recipients: must include result will be stored in the recipients.
vins: has to include the txids and vouts
*/
func SenderCreateOutputs(recipients []*Recipient, vins []*Vin, mainnet bool) error {
	var secretKeys [][32]byte

	// negate keys if necessary before summing them
	for _, vin := range vins {
		interim := *vin.SecretKey
		if vin.Taproot {
			interim = checkToNegate(*vin.SecretKey)
		}

		secretKeys = append(secretKeys, interim)
	}

	// sum up the privateKeys
	secretKeySum := RecursiveAddPrivateKeys(secretKeys)

	// derive A_sum from the private key sum aG + bG = [a+b]*G
	_, publicKeySum := btcec.PrivKeyFromBytes(secretKeySum[:])

	publicKeySumBytes := ConvertToFixedLength33(publicKeySum.SerializeCompressed())

	// compute inputHash
	inputHash, err := ComputeInputHash(vins, publicKeySumBytes)
	if err != nil {
		return err
	}

	// extract the pubKeys from the SP address
	for _, recipient := range recipients {
		scanPubKeyBytes, spendPubKeyBytes, err := DecodeSilentPaymentAddressToKeys(recipient.SilentPaymentAddress, mainnet)
		scanPubKey, err := btcec.ParsePubKey(scanPubKeyBytes[:])
		if err != nil {
			return err
		}
		spendPubKey, err := btcec.ParsePubKey(spendPubKeyBytes[:])
		if err != nil {
			return err
		}

		recipient.ScanPubKey, recipient.SpendPubKey = scanPubKey, spendPubKey
	}

	groups := matchRecipients(recipients)

	for receiverScanPubKey, groupRecipients := range groups {

		sharedSecret, err := CreateSharedSecret(receiverScanPubKey, secretKeySum, &inputHash)
		if err != nil {
			return err
		}

		var k uint32 = 0
		for _, recipient := range groupRecipients {
			outputPubKey, err := CreateOutputPubKey(sharedSecret, ConvertToFixedLength33(recipient.SpendPubKey.SerializeCompressed()), k)
			if err != nil {
				return err
			}
			recipient.Output = outputPubKey
			k++
		}
	}

	return nil
}

func checkToNegate(secretKey [32]byte) [32]byte {
	sk, pk := btcec.PrivKeyFromBytes(secretKey[:])
	if pk.Y().Bit(0) != 0 {
		// now we have to negate the secretKey
		return sk.Key.Negate().Bytes()
	} else {
		return secretKey
	}
}

func matchRecipients(recipients []*Recipient) map[[33]byte][]*Recipient {
	matches := make(map[[33]byte][]*Recipient)

	for _, recipient := range recipients {
		scanKey := ConvertToFixedLength33(recipient.ScanPubKey.SerializeCompressed())
		matches[scanKey] = append(matches[scanKey], recipient)
	}

	return matches
}
