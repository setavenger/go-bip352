package gobip352

import (
	"errors"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

func CreateAddress(scanPubKeyBytes, bMKeyBytes []byte, mainnet bool, version uint8) (string, error) {
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

func CreateLabeledAddress(scanPubKeyBytes, spendPubKeyBytes []byte, mainnet bool, version uint8, scanSecKey []byte, m uint32) (string, error) {
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

func DecodeSilentPaymentAddress(address string, mainnet bool) (string, []byte, uint8, error) {
	// check according to recommended length in BIP. underlying library does not do the check, so we do it here
	if len(address) > 1023 {
		return "", nil, 0, errors.New("exceeds BIP0352 recommended 1023 character limit")
	}
	hrp, data, err := bech32.DecodeNoLimit(address)
	if err != nil {
		return "", nil, 0, err
	}

	// check that we have the correct hrp
	if hrp == "sp" && !mainnet {
		return "", nil, 0, errors.New("hrp did not match network")
	}
	if hrp == "tsp" && mainnet {
		return "", nil, 0, errors.New("hrp did not match network")
	}

	// everything but the version

	version, data := data[0], data[1:]

	data, err = bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, 0, err
	}
	return hrp, data, version, nil
}

func DecodeSilentPaymentAddressToKeys(address string, mainnet bool) (scanPubKeyBytes []byte, spendPubKeyBytes []byte, err error) {
	_, data, _, err := DecodeSilentPaymentAddress(address, mainnet)
	if err != nil {
		return nil, nil, err
	}

	return data[:33], data[33:], err
}
