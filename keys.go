package bip352

import (
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/setavenger/blindbit-lib/utils"
	"github.com/tyler-smith/go-bip39"
)

// KeysFromMnemonic computes the scan and spend secret keys based on a mnemonic, a seedphrase (optional, leave as empty string if not needed) and chain
func KeysFromMnemonic(
	mnemonic, seedPassphrase string,
	mainnet bool,
) (
	scanSecret, spendSecret [32]byte,
	err error,
) {
	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, seedPassphrase)
	if err != nil {
		return
	}

	chainParams := chaincfg.MainNetParams
	if !mainnet {
		chainParams = chaincfg.SigNetParams
	}

	master, err := hdkeychain.NewMaster(seed, &chainParams)
	if err != nil {
		return
	}

	return DeriveKeysFromMaster(master, mainnet)
}

func DeriveKeysFromMaster(
	master *hdkeychain.ExtendedKey,
	mainnet bool,
) (
	scanSecret, spendSecret [32]byte,
	err error,
) {
	/*
		ScanDerivationPath = "m/352'/0'/0'/1'/0";
		SpendDerivationPath = "m/352'/0'/0'/0'/0";
	*/

	// m/352'
	purpose, err := master.Derive(352 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return
	}

	var coinType *hdkeychain.ExtendedKey

	if mainnet {
		// m/352'/0'
		coinType, err = purpose.Derive(0 + hdkeychain.HardenedKeyStart)
		if err != nil {
			return
		}
	} else {
		// m/352'/1'
		coinType, err = purpose.Derive(1 + hdkeychain.HardenedKeyStart)
		if err != nil {
			return
		}
	}

	// m/352'/0'/0'
	acct0, err := coinType.Derive(0 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return
	}

	// m/352'/0'/0'/1'
	scanExternal, err := acct0.Derive(1 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return
	}

	// m/352'/0'/0'/0'
	spendExternal, err := acct0.Derive(0 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return
	}

	scanKey, err := scanExternal.Derive(0)
	if err != nil {
		return
	}

	spendKey, err := spendExternal.Derive(0)
	if err != nil {
		return
	}

	secretKeyScan, err := scanKey.ECPrivKey()
	if err != nil {
		return
	}

	secretKeySpend, err := spendKey.ECPrivKey()
	if err != nil {
		return
	}

	return utils.ConvertToFixedLength32(secretKeyScan.Serialize()), utils.ConvertToFixedLength32(secretKeySpend.Serialize()), nil
}
