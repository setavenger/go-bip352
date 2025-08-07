package bip352

import (
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/setavenger/blindbit-lib/utils"
)

func CreateAddress(scanPubKeyBytes, bMKeyBytes *[33]byte, mainnet bool, version uint8) (string, error) {
	var data []byte
	//data = append(data, version)
	data = append(data, scanPubKeyBytes[:]...)
	data = append(data, bMKeyBytes[:]...)

	convertBits, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}

	// data = append(data, version)

	var finalSlice []byte
	finalSlice = append(finalSlice, version)
	finalSlice = append(finalSlice, convertBits...)

	if mainnet {
		return bech32.EncodeM("sp", finalSlice)
	} else {
		return bech32.EncodeM("tsp", finalSlice)
	}
}

func CreateLabeledAddress(
	scanPubKeyBytes, spendPubKeyBytes *[33]byte,
	mainnet bool,
	version uint8,
	scanSecKey *[32]byte,
	m uint32,
) (string, error) {
	labelTweak, err := CreateLabelTweak(scanSecKey, m)
	if err != nil {
		return "", err
	}

	label := PubKeyFromSecKey(&labelTweak)

	// todo does this need some sort of check additional check (e.g. point on the curve)?
	bMKeyBytes, err := CreateLabelledSpendPubKey(spendPubKeyBytes, label)
	if err != nil {
		return "", err
	}

	return CreateAddress(scanPubKeyBytes, &bMKeyBytes, mainnet, version)
}

// DecodeSilentPaymentAddress returns the components of an SP address
// Returns:
// 1. hrp
// 2. the raw byte data that was encoded
// 3. the version
// 4. the error, if one occurs
func DecodeSilentPaymentAddress(address string, mainnet bool) (string, []byte, uint8, error) {
	// check according to recommended length in BIP. underlying library does not do the check, so we do it here
	if len(address) > 1023 {
		return "", nil, 0, DecodingLimitExceeded
	}
	hrp, data, err := bech32.DecodeNoLimit(address)
	if err != nil {
		return "", nil, 0, err
	}

	// check that we have the correct hrp
	if hrp == "sp" && !mainnet {
		return "", nil, 0, AddressHRPError
	}
	if hrp == "tsp" && mainnet {
		return "", nil, 0, AddressHRPError
	}

	// extract everything but the version as data
	version, data := data[0], data[1:]

	data, err = bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, 0, err
	}
	return hrp, data, version, nil
}

func DecodeSilentPaymentAddressToKeys(
	address string,
	mainnet bool,
) (
	scanPubKeyBytes, spendPubKeyBytes [33]byte,
	err error,
) {
	_, data, _, err := DecodeSilentPaymentAddress(address, mainnet)
	if err != nil {
		return [33]byte{}, [33]byte{}, err
	}

	return utils.ConvertToFixedLength33(data[:33]), utils.ConvertToFixedLength33(data[33:]), err
}

// CreateLabelledSpendPubKey Returns the labeled spend pub key
//
// B_m = B_spend + label
func CreateLabelledSpendPubKey(spendPubKey, labelPubKey *[33]byte) ([33]byte, error) {
	return AddPublicKeys(spendPubKey, labelPubKey)
}

// IsSilentPaymentAddress determines whether an address is a silent payment address.
// Works only for silent payment v0
func IsSilentPaymentAddress(address string) bool {
	// only works for v1
	if len(address) == 116 && address[:2] == "sp" {
		return true
	}
	if len(address) == 117 && address[:3] == "tsp" {
		return true
	}
	return false
}
