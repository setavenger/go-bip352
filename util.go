package gobip352

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/ripemd160"
	"math/big"
	"sort"
)

func SumPublicKeys(pubKeys [][]byte) ([]byte, error) {
	var lastPubKeyBytes []byte

	for idx, bytesPubKey := range pubKeys {
		// for extracted keys which are only 32 bytes (taproot) we assume even parity
		// as we don't need the y-coordinate for any computation we can simply prepend 0x02
		if len(bytesPubKey) == 32 {
			bytesPubKey = bytes.Join([][]byte{{0x02}, bytesPubKey}, []byte{})
		}

		if idx == 0 {
			lastPubKeyBytes = bytesPubKey
			continue
		}

		var err error
		lastPubKeyBytes, err = AddPublicKeys(lastPubKeyBytes, bytesPubKey)
		if err != nil {
			return nil, err
		}
	}

	return lastPubKeyBytes, nil
}

func ReverseBytes(bytes []byte) []byte {
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return bytes
}
func TaggedHash(tag string, msg []byte) [32]byte {
	tagHash := sha256.Sum256([]byte(tag))
	data := append(tagHash[:], tagHash[:]...)
	data = append(data, msg...)
	return sha256.Sum256(data)
}

func SerU32(num uint32) ([]byte, error) {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, num)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), err
}

func AddPublicKeys(publicKeyBytes1, publicKeyBytes2 []byte) ([]byte, error) {
	publicKey1, err := btcec.ParsePubKey(publicKeyBytes1)
	if err != nil {
		return nil, err
	}

	publicKey2, err := btcec.ParsePubKey(publicKeyBytes2)
	if err != nil {
		return nil, err
	}

	sumX, sumY := btcec.S256().Add(publicKey1.X(), publicKey1.Y(), publicKey2.X(), publicKey2.Y())

	finalPubKey, err := ConvertPointsToPublicKey(sumX, sumY)
	if err != nil {
		return nil, err
	}

	return finalPubKey.SerializeCompressed(), nil
}

func AddPrivateKeys(secKey1, secKey2 []byte) []byte {
	// Convert hex strings to big integers
	key1 := new(big.Int).SetBytes(secKey1)
	key2 := new(big.Int).SetBytes(secKey2)

	curveParams := btcec.S256().Params()

	newKey := new(big.Int).Add(key1, key2)
	newKey.Mod(newKey, curveParams.N)
	return newKey.Bytes()
}

// RecursiveAddPrivateKeys this is a simple addition of given privateKeys
// Keep in mind that this function does not negate privateKeys this has to be done
// before calling this function
func RecursiveAddPrivateKeys(secretKeys [][]byte) []byte {
	var secretKeysSum []byte
	for i := 0; i < len(secretKeys); i++ {
		if i == 0 {
			secretKeysSum = secretKeys[0]
			continue
		}
		secretKeysSum = AddPrivateKeys(secretKeysSum, secretKeys[i])
	}

	return secretKeysSum
}

func MultPrivateKeys(secKey1, secKey2 []byte) []byte {
	key1 := new(big.Int).SetBytes(secKey1)
	key2 := new(big.Int).SetBytes(secKey2)

	curveParams := btcec.S256().Params()

	newKey := new(big.Int).Mul(key1, key2)
	newKey.Mod(newKey, curveParams.N)
	return newKey.Bytes()
}

func CreateLabelPublicKey(labelTweak []byte) []byte {
	_, pubKey := btcec.PrivKeyFromBytes(labelTweak)
	return pubKey.SerializeCompressed()
}

func ConvertPointsToPublicKey(x, y *big.Int) (*btcec.PublicKey, error) {
	// see how this can be written properly, but there does not seem to be a simple given API for that
	// in case big int omits leading zero

	sX := fmt.Sprintf("%x", x)
	sY := fmt.Sprintf("%x", y)
	sX = fmt.Sprintf("%064s", sX)
	sY = fmt.Sprintf("%064s", sY)
	decodeString, err := hex.DecodeString(fmt.Sprintf("04%s%s", sX, sY))
	if err != nil {
		return nil, err
	}

	finalPubKey, err := btcec.ParsePubKey(decodeString)
	if err != nil {
		return nil, err
	}

	return finalPubKey, nil
}

// FindSmallestOutpoint
// txid has to be in the normal human-readable format
func FindSmallestOutpoint(vins []*Vin) ([]byte, error) {
	if len(vins) == 0 {
		return nil, errors.New("vins were empty")
	}

	var outpoints [][]byte
	for _, vin := range vins {
		reversedTxid := ReverseBytes(vin.Txid)

		// Serialize the Vout as little-endian bytes
		voutBytes := new(bytes.Buffer)
		err := binary.Write(voutBytes, binary.LittleEndian, vin.Vout)
		if err != nil {
			return nil, err
		}
		// Concatenate reversed Txid and Vout bytes
		outpoint := append(reversedTxid, voutBytes.Bytes()...)

		// Add the serialized outpoint to the slice
		outpoints = append(outpoints, outpoint)
	}

	// Sort the slice of outpoints to find the lexicographically smallest one
	sort.Slice(outpoints, func(i, j int) bool {
		return bytes.Compare(outpoints[i], outpoints[j]) < 0
	})

	// Return the smallest outpoint
	return outpoints[0], nil
}

// Hash160 performs a RIPEMD160(SHA256(data)) hash on the given data
func Hash160(data []byte) []byte {
	sha256Hash := sha256.Sum256(data)
	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(sha256Hash[:]) // Hash the SHA256 hash
	return ripemd160Hasher.Sum(nil)
}

func NegatePublicKey(pk []byte) ([]byte, error) {
	pubKey, err := btcec.ParsePubKey(pk)
	if err != nil {
		return nil, err
	}
	curve := btcec.S256()
	interim := new(big.Int).Sub(curve.Params().P, pubKey.Y())
	newY := new(big.Int).Mod(interim, curve.Params().P)
	newKey, err := ConvertPointsToPublicKey(pubKey.X(), newY)
	if err != nil {
		return nil, err
	}

	return newKey.SerializeCompressed(), err
}

// ParseWitnessScript parses a hex-encoded witness script and returns the actual witness data as a list
func ParseWitnessScript(data []byte) ([][]byte, error) {

	// The first byte indicates the number of items in the witness data
	itemCount := int(data[0])
	var witnessData [][]byte
	i := 1 // Start index after the item count byte

	for j := 0; j < itemCount && i < len(data); j++ {
		if i >= len(data) {
			return nil, fmt.Errorf("script is shorter than expected")
		}

		// The first byte of each item indicates its length
		length := int(data[i])
		i++

		// Extract the witness data item based on the length
		if i+length > len(data) {
			return nil, fmt.Errorf("invalid length for witness data item")
		}
		item := data[i : i+length]

		// Append the hex-encoded item to the result list
		witnessData = append(witnessData, item)
		i += length
	}

	if len(witnessData) != itemCount {
		return nil, fmt.Errorf("actual item count does not match the expected count")
	}

	return witnessData, nil
}
