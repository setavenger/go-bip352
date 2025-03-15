package bip352

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/ripemd160"
)

func SumPublicKeys(pubKeys [][33]byte) ([33]byte, error) {
	var lastPubKeyBytes [33]byte

	for idx, bytesPubKey := range pubKeys {
		if idx == 0 {
			lastPubKeyBytes = bytesPubKey
			continue
		}

		var err error
		lastPubKeyBytes, err = AddPublicKeys(&lastPubKeyBytes, &bytesPubKey)
		if err != nil {
			return [33]byte{}, err
		}
	}

	return lastPubKeyBytes, nil
}

// ReverseBytes reverses the byte slice and returns that same byte slice
func ReverseBytes(bytes []byte) []byte {
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return bytes
}

// ReverseBytesCopy returns a new reversed byte slice
func ReverseBytesCopy(bytes []byte) []byte {
	bytesCopy := make([]byte, len(bytes))
	copy(bytesCopy, bytes)
	for i, j := 0, len(bytesCopy)-1; i < j; i, j = i+1, j-1 {
		bytesCopy[i], bytesCopy[j] = bytesCopy[j], bytesCopy[i]
	}
	return bytesCopy
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

// RecursiveAddPrivateKeys this is a simple addition of given privateKeys
// Keep in mind that this function does not negate privateKeys this has to be done
// before calling this function
func RecursiveAddPrivateKeys(secretKeys [][32]byte) [32]byte {
	var secretKeysSum [32]byte
	for i := 0; i < len(secretKeys); i++ {
		if i == 0 {
			secretKeysSum = secretKeys[0]
			continue
		}
		AddPrivateKeys(&secretKeysSum, &secretKeys[i])
	}

	return secretKeysSum
}

func ConvertPointsToPublicKey(x, y *big.Int) (*btcec.PublicKey, error) {
	pubkeyBytes := make([]byte, 65)
	pubkeyBytes[0] = 0x04
	x.FillBytes(pubkeyBytes[1:33])
	y.FillBytes(pubkeyBytes[33:])

	finalPubKey, err := btcec.ParsePubKey(pubkeyBytes)
	if err != nil {
		return nil, err
	}

	return finalPubKey, nil
}

// FindSmallestOutpoint
// txid has to be in the normal human-readable format
func FindSmallestOutpoint(vins []*Vin) ([]byte, error) {
	if len(vins) == 0 {
		return nil, ErrVinsEmpty
	}

	var outpoints [][]byte
	for _, vin := range vins {
		// we copy the byte slice here to avoid confusion with the endian format of the txid byte slice later on
		reversedTxid := ReverseBytesCopy(vin.Txid[:])

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

func ConvertToFixedLength32(input []byte) [32]byte {
	if len(input) != 32 {
		panic(fmt.Sprintf("wrong length expected 32 got %d", len(input)))
	}
	var output [32]byte
	copy(output[:], input)
	return output
}

func ConvertToFixedLength33(input []byte) [33]byte {
	if len(input) != 33 {
		panic(fmt.Sprintf("wrong length expected 33 got %d", len(input)))
	}
	var output [33]byte
	copy(output[:], input)
	return output
}
