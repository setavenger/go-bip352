//go:build !libsecp256k1

package bip352

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
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
	pubKey, err := btcec.ParsePubKey(publicComponent[:])
	if err != nil {
		return [33]byte{}, err
	}

	if inputHash != nil {
		secretComponent = MultPrivateKeys(secretComponent, *inputHash)
	}

	// Compute the scalar multiplication a * B (ECDH shared secret)
	x, y := btcec.S256().ScalarMult(pubKey.X(), pubKey.Y(), secretComponent[:])

	sharedSecretKey, err := ConvertPointsToPublicKey(x, y)
	if err != nil {
		return [33]byte{}, err
	}

	return ConvertToFixedLength33(sharedSecretKey.SerializeCompressed()), nil
}

func AddPublicKeys(publicKeyBytes1, publicKeyBytes2 *[33]byte) ([33]byte, error) {
	publicKey1, err := btcec.ParsePubKey(publicKeyBytes1[:])
	if err != nil {
		return [33]byte{}, err
	}

	publicKey2, err := btcec.ParsePubKey(publicKeyBytes2[:])
	if err != nil {
		return [33]byte{}, err
	}

	sumX, sumY := btcec.S256().Add(publicKey1.X(), publicKey1.Y(), publicKey2.X(), publicKey2.Y())

	finalPubKey, err := ConvertPointsToPublicKey(sumX, sumY)
	if err != nil {
		return [33]byte{}, err
	}

	return ConvertToFixedLength33(finalPubKey.SerializeCompressed()), nil
}

func AddPrivateKeys(secKey1, secKey2 *[32]byte) error {
	// Convert hex strings to big integers
	key1 := new(big.Int).SetBytes(secKey1[:])
	key2 := new(big.Int).SetBytes(secKey2[:])

	curveParams := btcec.S256().Params()

	newKey := new(big.Int).Add(key1, key2)
	newKey.Mod(newKey, curveParams.N)
	paddedResult := make([]byte, 32)
	copy(paddedResult[32-len(newKey.Bytes()):], newKey.Bytes())

	copy(secKey1[:], paddedResult)

	return nil
}

func NegatePublicKey(pk *[33]byte) error {
	pubKey, err := btcec.ParsePubKey(pk[:])
	if err != nil {
		return err
	}
	curve := btcec.S256()
	interim := new(big.Int).Sub(curve.Params().P, pubKey.Y())
	newY := new(big.Int).Mod(interim, curve.Params().P)
	newKey, err := ConvertPointsToPublicKey(pubKey.X(), newY)
	if err != nil {
		return err
	}

	val := newKey.SerializeCompressed()
	copy(pk[:], val)

	return err
}

func MultPrivateKeys(secKey1, secKey2 [32]byte) [32]byte {
	key1 := new(big.Int).SetBytes(secKey1[:])
	key2 := new(big.Int).SetBytes(secKey2[:])

	curveParams := btcec.S256().Params()

	newKey := new(big.Int).Mul(key1, key2)
	newKey.Mod(newKey, curveParams.N)
	return ConvertToFixedLength32(newKey.Bytes())
}

func PubKeyFromSecKey(secKey *[32]byte) [33]byte {
	_, pubKey := btcec.PrivKeyFromBytes(secKey[:])
	return ConvertToFixedLength33(pubKey.SerializeCompressed())
}

// func CreateLabelPublicKey(labelTweak [32]byte) [33]byte {
// 	_, pubKey := btcec.PrivKeyFromBytes(labelTweak[:])
// 	return ConvertToFixedLength33(pubKey.SerializeCompressed())
// }
