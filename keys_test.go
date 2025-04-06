package bip352

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

func TestDeriveKeysFromMaster(t *testing.T) {
	scanKeyTarget, _ := hex.DecodeString("78e7fd7d2b7a2c1456709d147021a122d2dccaafeada040cc1002083e2833b09")
	spendKeyTarget, _ := hex.DecodeString("c88567742d5019d7ccc81f6e82cef8ef01997a6a3761cc9166036b580549539b")

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	seed := bip39.NewSeed(mnemonic, "")

	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Errorf("error creating master key: %v", err)
		return
	}

	scanSecret, spendSecret, err := DeriveKeysFromMaster(master, true)
	if err != nil {
		t.Errorf("error deriving keys: %v", err)
		return
	}

	if !bytes.Equal(scanSecret[:], scanKeyTarget) {
		t.Errorf("error deriving keys: expected %x, got %x", scanKeyTarget, scanSecret)
		return
	}
	if !bytes.Equal(spendSecret[:], spendKeyTarget) {
		t.Errorf("error deriving keys: expected %x, got %x", spendKeyTarget, spendSecret)
		return
	}
}
