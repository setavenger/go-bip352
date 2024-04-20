package gobip352

import (
	"bytes"
)

//secp256k1_silentpayments_receiver_scan_outputs

type FoundOutputs struct {
	Output      []byte // 32 byte x-only pubKey
	SecKeyTweak []byte // 32 byte tweak for the output
	Label       []byte // 33 byte public key of the label is a label was matched
}

type Label struct {
	PubKey  []byte // 33 byte compressed pubKey of the label
	Tweak   []byte // 32 byte tweak/secKey to produce the labels pubKey
	Address string // the corresponding address for the label
}

// ReceiverScanTransaction
// scanKey: 32 byte private scanKey of the receiver
// receiverSpendPubKey: 33 byte spend pubKey of the receiver
// txOutputs: x-only outputs of the specific transaction
// labels: existing label public keys as bytes [wallets should always check for the change label]
// publicComponent: 33 byte either A_sum or tweaked (A_sum * input_hash) if tweaked inputHash should be nil or the computation will be flawed
// inputHash: 32 byte can be nil if publicComponent is a tweak and already includes the input_hash
func ReceiverScanTransaction(scanKey, receiverSpendPubKey []byte, labels []Label, txOutputs [][]byte, publicComponent, inputHash []byte) ([]*FoundOutputs, error) {

	// todo should probably check inputs before computation especially the labels
	var foundOutputs []*FoundOutputs

	var k uint32 = 0
	for true {
		sharedSecret, err := CreateSharedSecret(publicComponent, scanKey, inputHash)
		if err != nil {
			return nil, err
		}

		var outputPubKey []byte
		var tweak []byte
		outputPubKey, tweak, err = CreateOutputPubKeyTweak(sharedSecret, receiverSpendPubKey, k)
		if err != nil {
			return nil, err
		}

		var found bool
		for i, txOutput := range txOutputs {
			if bytes.Equal(outputPubKey, txOutput) {
				foundOutputs = append(foundOutputs, &FoundOutputs{
					Output:      txOutput,
					SecKeyTweak: tweak,
					Label:       nil,
				})
				txOutputs = append(txOutputs[:i], txOutputs[i+1:]...)
				found = true
				k++
				break // found the matching txOutput for outputPubKey, don't try the rest
			}

			if labels == nil {
				continue
			}

			// now check the labels
			var foundLabel *Label

			// start with normal output
			foundLabel, err = MatchLabels(append([]byte{0x02}, txOutput...), outputPubKey, labels)
			if err != nil {
				return nil, err
			}
			if foundLabel != nil {
				tweak = AddPrivateKeys(tweak, foundLabel.Tweak) // labels have a modified tweak
				foundOutputs = append(foundOutputs, &FoundOutputs{
					Output:      txOutput,
					SecKeyTweak: tweak,
					Label:       nil,
				})
				txOutputs = append(txOutputs[:i], txOutputs[i+1:]...)
				found = true
				k++
				continue
			}

			// try the negated output for the label
			var txOutputNegated []byte
			txOutputNegated, err = NegatePublicKey(append([]byte{0x02}, txOutput...))
			if err != nil {
				return nil, err
			}

			foundLabel, err = MatchLabels(txOutputNegated, outputPubKey, labels)
			if err != nil {
				return nil, err
			}
			if foundLabel != nil {
				tweak = AddPrivateKeys(tweak, foundLabel.Tweak) // labels have a modified tweak
				foundOutputs = append(foundOutputs, &FoundOutputs{
					Output:      txOutputNegated,
					SecKeyTweak: tweak,
					Label:       nil,
				})
				txOutputs = append(txOutputs[:i], txOutputs[i+1:]...)
				found = true
				k++
				continue
			}
		}

		if !found {
			break
		}
	}
	return foundOutputs, nil
}

func MatchLabels(txOutput, pk []byte, labels []Label) (*Label, error) {
	// subtraction is adding a negated value
	pkNeg, err := NegatePublicKey(pk)
	if err != nil {
		return nil, err
	}

	// todo is this the best place to prepend to compressed
	labelMatch, err := AddPublicKeys(txOutput, pkNeg)
	if err != nil {
		return nil, err
	}

	for _, label := range labels {
		if bytes.Equal(labelMatch, label.PubKey) {
			return &label, nil
		}
	}

	return nil, nil
}
