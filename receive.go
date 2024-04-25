package gobip352

import (
	"bytes"
)

type FoundOutput struct {
	Output      [32]byte // x-only pubKey
	SecKeyTweak [32]byte // tweak for the output
	Label       *Label   // the label that was matched if there was a label to match
}

type Label struct {
	PubKey  [33]byte `json:"pub_key"` // compressed pubKey of the label
	Tweak   [32]byte `json:"tweak"`   // tweak/secKey to produce the labels pubKey
	Address string   `json:"address"` // todo the corresponding address for the label, still needs a good API for instantiating with this data
	M       uint32   `json:"m"`
}

// ReceiverScanTransaction
// scanKey: scanning secretKey of the receiver
// receiverSpendPubKey: spend pubKey of the receiver
// txOutputs: x-only outputs of the specific transaction
// labels: existing label public keys as bytes [wallets should always check for the change label]
// publicComponent: either A_sum or tweaked (A_sum * input_hash) if tweaked inputHash should be nil or the computation will be flawed
// inputHash: 32 byte can be nil if publicComponent is a tweak and already includes the input_hash
func ReceiverScanTransaction(scanKey [32]byte, receiverSpendPubKey [33]byte, labels []Label, txOutputs [][32]byte, publicComponent [33]byte, inputHash *[32]byte) ([]*FoundOutput, error) {

	// todo should probably check inputs before computation especially the labels
	var foundOutputs []*FoundOutput

	var k uint32 = 0
	for true {
		sharedSecret, err := CreateSharedSecret(publicComponent, scanKey, inputHash)
		if err != nil {
			return nil, err
		}

		var outputPubKey [32]byte
		var tweak [32]byte
		outputPubKey, tweak, err = CreateOutputPubKeyTweak(sharedSecret, receiverSpendPubKey, k)
		if err != nil {
			return nil, err
		}

		var found bool
		for i, txOutput := range txOutputs {
			if bytes.Equal(outputPubKey[:], txOutput[:]) {
				foundOutputs = append(foundOutputs, &FoundOutput{
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

			prependedTxOutput := ConvertToFixedLength33(append([]byte{0x02}, txOutput[:]...))
			prependedOutputPubKey := ConvertToFixedLength33(append([]byte{0x02}, outputPubKey[:]...))

			// start with normal output
			foundLabel, err = MatchLabels(prependedTxOutput, prependedOutputPubKey, labels)
			if err != nil {
				return nil, err
			}
			if foundLabel != nil {
				tweak = AddPrivateKeys(tweak, foundLabel.Tweak) // labels have a modified tweak
				foundOutputs = append(foundOutputs, &FoundOutput{
					Output:      txOutput,
					SecKeyTweak: tweak,
					Label:       foundLabel,
				})
				txOutputs = append(txOutputs[:i], txOutputs[i+1:]...)
				found = true
				k++
				break
			}

			// try the negated output for the label
			var txOutputNegatedCompressed [33]byte

			txOutputNegatedCompressed, err = NegatePublicKey(prependedTxOutput)
			if err != nil {
				return nil, err
			}

			foundLabel, err = MatchLabels(txOutputNegatedCompressed, prependedOutputPubKey, labels)
			if err != nil {
				return nil, err
			}
			if foundLabel != nil {
				tweak = AddPrivateKeys(tweak, foundLabel.Tweak) // labels have a modified tweak
				foundOutputs = append(foundOutputs, &FoundOutput{
					Output:      ConvertToFixedLength32(txOutputNegatedCompressed[1:]),
					SecKeyTweak: tweak,
					Label:       foundLabel,
				})
				txOutputs = append(txOutputs[:i], txOutputs[i+1:]...)
				found = true
				k++
				break
			}
		}

		if !found {
			break
		}
	}
	return foundOutputs, nil
}

func MatchLabels(txOutput, pk [33]byte, labels []Label) (*Label, error) {
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
		if bytes.Equal(labelMatch[1:], label.PubKey[1:]) {
			return &label, nil
		}
	}

	return nil, nil
}
