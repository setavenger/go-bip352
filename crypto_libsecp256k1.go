//go:build libsecp256k1

package bip352

import (
	golibsecp256k1 "github.com/setavenger/go-libsecp256k1"
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
func CreateSharedSecret(
	publicComponent [33]byte,
	secretComponent [32]byte,
	inputHash *[32]byte,
) ([33]byte, error) {
	if inputHash != nil {
		err := golibsecp256k1.MultPrivateKeys(&secretComponent, inputHash)
		if err != nil {
			return [33]byte{}, err
		}
	}

	err := golibsecp256k1.PubKeyTweakMul(&publicComponent, secretComponent)
	if err != nil {
		return [33]byte{}, err
	}
	return publicComponent, nil
}

func AddPrivateKeys(secKey1, secKey2 *[32]byte) error {
	return golibsecp256k1.SecKeyAdd(secKey1, *secKey2)
}

func AddPublicKeys(publicKeyBytes1, publicKeyBytes2 *[33]byte) ([33]byte, error) {
	return golibsecp256k1.PubKeyAdd(publicKeyBytes1, publicKeyBytes2)
}

func NegatePublicKey(pk *[33]byte) error {
	return golibsecp256k1.PubKeyNegate(pk)
}

func MultPrivateKeys(secKey1, secKey2 *[32]byte) error {
	return golibsecp256k1.MultPrivateKeys(secKey1, secKey2)
}

func PubKeyFromSecKey(secKey *[32]byte) [33]byte {
	return golibsecp256k1.PubKeyFromSecKey(secKey)
}

// func CreateLabelPublicKey(labelTweak [32]byte) [33]byte {
// 	return PubKeyFromSecKey(labelTweak)
// }
