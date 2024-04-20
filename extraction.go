package gobip352

import (
	"bytes"
)

// NumsH = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
var NumsH = []byte{80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138, 90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192}

// extractPubKey
// this routine is not optimised yet and might not be able to parse all edge cases.
// todo needs some more robustness for non-standard UTXOs
// todo it does pass the test vectors
func extractPubKey(vin *Vin) ([]byte, TypeUTXO, error) {
	var pubKey []byte
	var utxoType TypeUTXO

	var err error
	if isP2TR(vin.ScriptPubKey) {
		pubKey, err = extractPubKeyFromP2TR(vin)
		if err != nil {
			return nil, NoType, err
		}
		// don't think this is needed
		//if pubKey == nil {
		//	return nil, NoType, errors.New(fmt.Sprintf("could not extract from p2tr: %x", vin.ScriptPubKey))
		//}
		if pubKey != nil {
			utxoType = P2TR
		}
	} else if isP2WPKH(vin.ScriptPubKey) {
		// last element in the witness data is public key; skip uncompressed
		if len(vin.Witness[len(vin.Witness)-1]) == 33 {
			pubKey = vin.Witness[len(vin.Witness)-1]
			utxoType = P2WPKH
		}
	} else if isP2PKH(vin.ScriptPubKey) {
		pubKey = extractFromP2PKH(vin)
		// don't think this is needed
		//if pubKey == nil {
		//	return nil, NoType, errors.New(fmt.Sprintf("could not extract from p2pkh %x", vin.ScriptSig))
		//}
		if pubKey != nil {
			utxoType = P2PKH
		}
	} else if isP2SH(vin.ScriptPubKey) {
		// P2SH-P2WPKH which is seen as a p2sh
		if len(vin.ScriptSig) == 23 {
			if bytes.Equal(vin.ScriptSig[:3], []byte{0x16, 0x00, 0x14}) {
				if len(vin.Witness[len(vin.Witness)-1]) == 33 {
					pubKey = vin.Witness[len(vin.Witness)-1]
					utxoType = P2SH
				}
			}
		}
	}

	return pubKey, utxoType, nil
}

// extractPublicKey tries to find a public key within the given scriptSig.
func extractFromP2PKH(vin *Vin) []byte {

	spkHash := vin.ScriptPubKey[3:23] // Skip op_codes and grab the hash

	// todo inefficient implementation copied from reference implementation
	//  should be improved upon
	for i := len(vin.ScriptSig); i >= 33; i-- {
		pubKey := vin.ScriptSig[i-33 : i]
		pubKeyHash := Hash160(pubKey)
		if bytes.Equal(pubKeyHash, spkHash) {
			return pubKey
		}
	}

	return nil
}

func extractPubKeyFromP2TR(vin *Vin) ([]byte, error) {
	witnessStack := vin.Witness

	if len(witnessStack) >= 1 {
		// Remove annex if present
		if len(witnessStack) > 1 && bytes.Equal(witnessStack[len(witnessStack)-1], []byte{0x50}) {
			witnessStack = witnessStack[:len(witnessStack)-1]
		}

		if len(witnessStack) > 1 {
			// Script-path spend
			controlBlock := witnessStack[len(witnessStack)-1]
			// Control block format: <control byte> <32-byte internal key> [<32-byte hash>...]
			if len(controlBlock) >= 33 {
				internalKey := controlBlock[1:33]

				if bytes.Equal(internalKey, NumsH) {
					// Skip if internal key is NUMS_H
					return nil, nil
				}

				return vin.ScriptPubKey[2:], nil
			}
		}

		return vin.ScriptPubKey[2:], nil
	}

	return nil, nil
}

// isP2TR checks if the script is a P2TR (Pay-to-Taproot) type.
func isP2TR(spk []byte) bool {
	if len(spk) != 34 {
		return false
	}
	// OP_1 OP_PUSHBYTES_32 <32 bytes>
	return spk[0] == 0x51 && spk[1] == 0x20
}

// isP2WPKH checks if the script is a P2WPKH (Pay-to-Witness-Public-Key-Hash) type.
func isP2WPKH(spk []byte) bool {
	if len(spk) != 22 {
		return false
	}
	// OP_0 OP_PUSHBYTES_20 <20 bytes>
	return spk[0] == 0x00 && spk[1] == 0x14
}

// isP2SH checks if the script is a P2SH (Pay-to-Script-Hash) type.
func isP2SH(spk []byte) bool {
	if len(spk) != 23 {
		return false
	}
	// OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUAL
	return spk[0] == 0xA9 && spk[1] == 0x14 && spk[len(spk)-1] == 0x87
}

// isP2PKH checks if the script is a P2PKH (Pay-to-Public-Key-Hash) type.
func isP2PKH(spk []byte) bool {
	if len(spk) != 25 {
		return false
	}
	// OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
	return spk[0] == 0x76 && spk[1] == 0xA9 && spk[2] == 0x14 && spk[len(spk)-2] == 0x88 && spk[len(spk)-1] == 0xAC
}
