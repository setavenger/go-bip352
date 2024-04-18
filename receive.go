package gobip352

import "github.com/btcsuite/btcd/btcec/v2"

//secp256k1_silentpayments_receiver_scan_outputs

type FoundOutputs struct {
	Output [32]byte
	Tweak  [32]byte
	Label  [33]byte
}

// ReceiverScanOutputs
// sharedSecret: the ecdh shared secret computed
// receiverSpendPubKey: spend pubKey of the receiver
// txOutputs: x-only outputs of the specific transaction
// labels: existing label Public keys as bytes
func ReceiverScanOutputs(sharedSecret []byte, receiverSpendPubKey *btcec.PublicKey, txOutputs [][]byte, labels [][]byte) ([]FoundOutputs, error) {
	return nil, nil
}
