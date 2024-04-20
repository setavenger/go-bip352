package gobip352

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
)

type TypeUTXO uint8

const (
	P2TR TypeUTXO = iota
	P2WPKH
	P2PKH
	P2SH

	NoType
)

// CreateSharedSecret
// The public component is dependent on whether this function is called from the sender or receiver side.
// The input_hash is the same for both sides.
// The input_hash can be nil if the publicComponent already incorporates the inputHash in case of a tweak as it would be for light clients
//
// For the sender publicComponent is B_scan and secretComponent is a_sum
//
// shared_secret = (a_sum * input_hash) * B_scan   [Sender]
//
// For the receiver publicComponent is A_sum and the secretComponent is b_scan
//
// shared_secret = (b_scan * input_hash) * A_sum   [Receiver, Full node scenario]
//
// shared_secret = b_scan * A_tweaked   [Receiver, Light client scenario]
func CreateSharedSecret(publicComponent []byte, secretComponent []byte, inputHash []byte) ([]byte, error) {
	pubKey, err := btcec.ParsePubKey(publicComponent)
	if err != nil {
		return nil, err
	}

	if inputHash != nil {
		secretComponent = MultPrivateKeys(secretComponent, inputHash)
	}

	// Compute the scalar multiplication a * B (ECDH shared secret)
	x, y := btcec.S256().ScalarMult(pubKey.X(), pubKey.Y(), secretComponent)

	sharedSecretKey, err := ConvertPointsToPublicKey(x, y)
	if err != nil {
		return nil, err
	}

	return sharedSecretKey.SerializeCompressed(), nil
}

// CreateOutputPubKey
// returns 32 byte x-only pubKey
func CreateOutputPubKey(sharedSecret []byte, receiverSpendPubKey []byte, k uint32) ([]byte, error) {
	// Calculate and return P_output_xonly = B_spend + t_k * G
	tkScalar, err := ComputeTK(sharedSecret, k)
	if err != nil {
		return nil, err
	}

	// t_k * G
	_, tkScalarPubKey := btcec.PrivKeyFromBytes(tkScalar)

	// P_output_xonly = B_spend + t_k * G
	outputPubKey, err := AddPublicKeys(receiverSpendPubKey, tkScalarPubKey.SerializeCompressed())
	if err != nil {
		return nil, err
	}

	// return x-only key
	return outputPubKey[1:], nil
}

// CreateOutputPubKeyTweak
// same as CreateOutputPubKey but this also returns the tweak of the output and the 33 byte compressed output
func CreateOutputPubKeyTweak(sharedSecret []byte, receiverSpendPubKey []byte, k uint32) ([]byte, []byte, error) {
	// Calculate and return P_output_xonly = B_spend + t_k * G
	tkScalar, err := ComputeTK(sharedSecret, k)
	if err != nil {
		return nil, nil, err
	}

	// t_k * G
	_, tkScalarPubKey := btcec.PrivKeyFromBytes(tkScalar)

	// P_output_xonly = B_spend + t_k * G
	outputPubKey, err := AddPublicKeys(receiverSpendPubKey, tkScalarPubKey.SerializeCompressed())
	if err != nil {
		return nil, nil, err
	}

	// return x-only key
	return outputPubKey, tkScalar, nil
}

func CreatePublicTweakData(publicKeys []*btcec.PublicKey, smallestOutpoint []byte) ([]byte, error) {
	return nil, nil
}

func ComputeTK(sharedSecret []byte, k uint32) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.Write(sharedSecret)
	serializedK, err := SerU32(k)
	if err != nil {
		return nil, err
	}
	buffer.Write(serializedK)
	tKScalar := TaggedHash("BIP0352/SharedSecret", buffer.Bytes())
	return tKScalar[:], err
}

func CreateLabelTweak(scanSecKey []byte, m uint32) ([]byte, error) {
	serialisedM, err := SerU32(m)
	if err != nil {
		return []byte{}, err
	}

	hash := TaggedHash("BIP0352/Label", append(scanSecKey, serialisedM...))
	return hash[:], nil
}

func CreateLabel(scanSecKey []byte, m uint32) (Label, error) {
	labelTweak, err := CreateLabelTweak(scanSecKey, m)
	if err != nil {
		return Label{}, err
	}

	labelPubKey := CreateLabelPublicKey(labelTweak)

	return Label{Tweak: labelTweak, PubKey: labelPubKey}, err
}

// ComputeInputHash computes the input_hash for a transaction as per the specification.
// vins: does not need to contain public key or secret key, only needs the txid and vout; txid has to be in the normal human-readable format
// sumPublicKeys: 33 byte compressed public key sum of the inputs for shared derivation https://github.com/josibake/bips/blob/silent-payments-bip/bip-0352.mediawiki#inputs-for-shared-secret-derivation
func ComputeInputHash(vins []*Vin, publicKeySum []byte) ([]byte, error) {
	// Find the lexicographically smallest outpoint (outpointL)
	smallestOutpoint, err := FindSmallestOutpoint(vins) // Implement this function based on your requirements
	if err != nil {
		return nil, fmt.Errorf("error finding smallest outpoint: %w", err)
	}

	// Concatenate outpointL and A_sum
	buffer := append(smallestOutpoint, publicKeySum...)

	// Compute input_hash using domain-separated hash
	inputHash := TaggedHash("BIP0352/Inputs", buffer)

	return inputHash[:], nil
}

func GenerateSignature(secSpend, privKeyTweak, hash, aux []byte) ([]byte, error) {
	return nil, nil
}
