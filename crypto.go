package bip352

import (
	"crypto/sha256"

	golibsecp256k1 "github.com/setavenger/go-libsecp256k1"
	"golang.org/x/crypto/ripemd160"
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
//
// publicComponent is modified in place
func CreateSharedSecret(
	publicComponent *[33]byte,
	secretComponent *[32]byte,
	inputHash *[32]byte,
) (*[33]byte, error) {
	var err error
	if inputHash != nil {
		err = golibsecp256k1.MultPrivateKeys(secretComponent, inputHash)
		if err != nil {
			return nil, err
		}
	}

	err = golibsecp256k1.PubKeyTweakMul(publicComponent, secretComponent)
	if err != nil {
		return nil, err
	}

	return publicComponent, nil
}

func AddPublicKeys(publicKeyBytes1, publicKeyBytes2 *[33]byte) ([33]byte, error) {
	return golibsecp256k1.PubKeyAdd(publicKeyBytes1, publicKeyBytes2)
}

func AddPrivateKeys(secKey1, secKey2 *[32]byte) error {
	return golibsecp256k1.SecKeyAdd(secKey1, secKey2)
}

func NegatePublicKey(pk *[33]byte) error {
	return golibsecp256k1.PubKeyNegate(pk)
}

func MultPrivateKeys(secKey1, secKey2 *[32]byte) error { // modify to return error instead of new key. work with pointers
	return golibsecp256k1.MultPrivateKeys(secKey1, secKey2)
}

func PubKeyFromSecKey(secKey *[32]byte) *[33]byte {
	return golibsecp256k1.PubKeyFromSecKey(secKey)
}

func SumPublicKeys(pubKeys [][33]byte) (out *[33]byte, err error) {
	var lastPubKey [33]byte

	for idx, pubKey := range pubKeys {
		if idx == 0 {
			lastPubKey = pubKey
		} else {
			lastPubKey, err = golibsecp256k1.PubKeyAdd(&lastPubKey, &pubKey)
			if err != nil {
				return nil, err
			}
		}
	}
	return &lastPubKey, nil
}

// Hashes

// HashTagged hashes a tag and a message using SHA256(SHA256(tag || data))
func HashTagged(tag string, msg []byte) [32]byte {
	tagHash := sha256.Sum256([]byte(tag))
	data := append(tagHash[:], tagHash[:]...)
	data = append(data, msg...)
	return sha256.Sum256(data)
}

// Hash160 performs a RIPEMD160(SHA256(data)) hash on the given data
func Hash160(data []byte) []byte {
	sha256Hash := sha256.Sum256(data)
	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(sha256Hash[:]) // Hash the SHA256 hash
	return ripemd160Hasher.Sum(nil)
}
