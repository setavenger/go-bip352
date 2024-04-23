package gobip352

import (
	"github.com/btcsuite/btcd/btcutil/bech32"
)

func CreateAddress(scanPubKeyBytes, bMKeyBytes [33]byte, mainnet bool, version uint8) (string, error) {
	var data []byte
	//data = append(data, version)
	data = append(data, scanPubKeyBytes[:]...)
	data = append(data, bMKeyBytes[:]...)

	convertBits, err := bech32.ConvertBits(data, 8, 5, true)
	data = append(data, version)

	var finalSlice []byte
	finalSlice = append(finalSlice, version)
	finalSlice = append(finalSlice, convertBits...)

	if err != nil {
		return "", err
	}
	if mainnet {
		return bech32.EncodeM("sp", finalSlice)
	} else {
		return bech32.EncodeM("tsp", finalSlice)
	}
}

func CreateLabeledAddress(scanPubKeyBytes, spendPubKeyBytes [33]byte, mainnet bool, version uint8, scanSecKey [32]byte, m uint32) (string, error) {
	labelTweak, err := CreateLabelTweak(scanSecKey, m)
	if err != nil {
		return "", err
	}

	label := CreateLabelPublicKey(labelTweak)

	// todo does this need some sort of check additional check (e.g. point on the curve)?
	bMKeyBytes, err := AddPublicKeys(spendPubKeyBytes, label)
	if err != nil {
		return "", err
	}

	return CreateAddress(scanPubKeyBytes, bMKeyBytes, mainnet, version)
}

// DecodeSilentPaymentAddress
// Returns:
// 1. hrp
// 2. the raw byte data that was encoded
// 3. the version
// 4. the error, if one occurs
func DecodeSilentPaymentAddress(address string, mainnet bool) (string, []byte, uint8, error) {
	// check according to recommended length in BIP. underlying library does not do the check, so we do it here
	if len(address) > 1023 {
		return "", nil, 0, DecodingLimitExceeded{}
	}
	hrp, data, err := bech32.DecodeNoLimit(address)
	if err != nil {
		return "", nil, 0, err
	}

	// check that we have the correct hrp
	if hrp == "sp" && !mainnet {
		return "", nil, 0, AddressHRPError{}
	}
	if hrp == "tsp" && mainnet {
		return "", nil, 0, AddressHRPError{}
	}

	// everything but the version

	version, data := data[0], data[1:]

	data, err = bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, 0, err
	}
	return hrp, data, version, nil
}

func DecodeSilentPaymentAddressToKeys(address string, mainnet bool) (scanPubKeyBytes, spendPubKeyBytes [33]byte, err error) {
	_, data, _, err := DecodeSilentPaymentAddress(address, mainnet)
	if err != nil {
		return [33]byte{}, [33]byte{}, err
	}

	return ConvertToFixedLength33(data[:33]), ConvertToFixedLength33(data[33:]), err
}

// CreateLabelledSpendPubKey Returns the labeled spend pub key
//
// B_m = B_spend + label
//
// todo should this be included?
func CreateLabelledSpendPubKey(spendPubKey, labelPubKey [33]byte) ([33]byte, error) {
	return AddPublicKeys(spendPubKey, labelPubKey)
}
