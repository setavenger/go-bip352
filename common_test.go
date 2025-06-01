package bip352

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/setavenger/blindbit-lib/utils"
)

func TestFindSmallestOutpoint(t *testing.T) {

	vin1Txid, _ := hex.DecodeString("3065242135dac11414f16db5a9dec805d95e82d1bb14361578e87b098c969e3e")
	vin1Vout := 136
	vin2Txid, _ := hex.DecodeString("3065242135dac11414f16db5a9dec805d95e82d1bb14361578e87b098c969e3e")
	vin2Vout := 202
	vin3Txid, _ := hex.DecodeString("3065242135dac11414f16db5a9dec805d95e82d1bb14361578e87b098c969e3e")
	vin3Vout := 204
	vin4Txid, _ := hex.DecodeString("3065242135dac11414f16db5a9dec805d95e82d1bb14361578e87b098c969e3e")
	vin4Vout := 383
	vin5Txid, _ := hex.DecodeString("5e3c7e1837e959d22769df649972b32166c6acd38c223a9c61829abbad71dda4")
	vin5Vout := 0
	vin6Txid, _ := hex.DecodeString("634c4f8132abeb93112877db77bc3b9c1484d996cb733dd97e825faf4b9fb2ce")
	vin6Vout := 1

	var vins = []*Vin{
		{
			Txid: utils.ConvertToFixedLength32(vin1Txid),
			Vout: uint32(vin1Vout),
		},
		{
			Txid: utils.ConvertToFixedLength32(vin2Txid),
			Vout: uint32(vin2Vout),
		},
		{
			Txid: utils.ConvertToFixedLength32(vin3Txid),
			Vout: uint32(vin3Vout),
		},
		{
			Txid: utils.ConvertToFixedLength32(vin4Txid),
			Vout: uint32(vin4Vout),
		},
		{
			Txid: utils.ConvertToFixedLength32(vin5Txid),
			Vout: uint32(vin5Vout),
		},
		{
			Txid: utils.ConvertToFixedLength32(vin6Txid),
			Vout: uint32(vin6Vout),
		},
	}
	smallestOutpoint, err := FindSmallestOutpoint(vins)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	// fmt.Printf("%x\n", smallestOutpoint)

	goal, _ := hex.DecodeString("3e9e968c097be878153614bbd1825ed905c8dea9b56df11414c1da35212465307f010000")
	if !bytes.Equal(smallestOutpoint, goal) {
		t.Errorf("Error: smallest outpoint was incorrect %x != %x", smallestOutpoint, goal)
		return
	}

	vin1Txid, _ = hex.DecodeString("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
	vin1Vout = 3
	vin2Txid, _ = hex.DecodeString("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
	vin2Vout = 7

	vins = []*Vin{
		{
			Txid: utils.ConvertToFixedLength32(vin1Txid),
			Vout: uint32(vin1Vout),
		},
		{
			Txid: utils.ConvertToFixedLength32(vin2Txid),
			Vout: uint32(vin2Vout),
		},
	}

	smallestOutpoint, err = FindSmallestOutpoint(vins)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	// fmt.Printf("%x\n", smallestOutpoint)

	goal, _ = hex.DecodeString("169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f403000000")
	if !bytes.Equal(smallestOutpoint, goal) {
		t.Errorf("Error: smallest outpoint was incorrect %x != %x", smallestOutpoint, goal)
		return
	}

	vin1Txid, _ = hex.DecodeString("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
	vin1Vout = 426
	vin2Txid, _ = hex.DecodeString("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
	vin2Vout = 171

	vins = []*Vin{
		{
			Txid: utils.ConvertToFixedLength32(vin1Txid),
			Vout: uint32(vin1Vout),
		},
		{
			Txid: utils.ConvertToFixedLength32(vin2Txid),
			Vout: uint32(vin2Vout),
		},
	}

	smallestOutpoint, err = FindSmallestOutpoint(vins)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	// fmt.Printf("%x\n", smallestOutpoint)

	goal, _ = hex.DecodeString("169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4aa010000")
	if !bytes.Equal(smallestOutpoint, goal) {
		t.Errorf("Error: smallest outpoint was incorrect %x != %x", smallestOutpoint, goal)
		return
	}
}
