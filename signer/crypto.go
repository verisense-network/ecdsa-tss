package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"

	crypto_tss "github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/ckd"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/crypto"
)

var path = []uint32{0x09, 0x00, 0x01, 0x02, 0x01, 0x04}

func numberToPartyID(number uint16) *tss.PartyID {
	return tss.NewPartyID(fmt.Sprintf("%d", number), "", big.NewInt(int64(number)))
}
func numbersToPartyIDs(numbers []uint16) []*tss.PartyID {
	var partyIDs []*tss.PartyID
	for _, number := range numbers {
		partyIDs = append(partyIDs, numberToPartyID(number))
	}
	return tss.SortPartyIDs(partyIDs)
}

func locatePartyIndex(params *tss.Parameters, id *tss.PartyID) int {
	for index, p := range params.Parties().IDs() {
		if bytes.Equal(p.Key, id.Key) {
			return index
		}
	}
	return -1
}
func convertU32ToU16(num uint32) (uint16, error) {
	if num > math.MaxUint16 {
		return 0, fmt.Errorf("number must be less than or equal to %d", math.MaxUint16)
	}
	return uint16(num), nil
}
func curveIdToCurve(curveId uint16) elliptic.Curve {
	if curveId == 0 {
		return tss.S256()
	}
	return tss.Edwards()
}

// return localSaveData and public key
func bytesToLocalPartySaveData(curveId uint16, data []byte) (*keygen.LocalPartySaveData, error) {
	var localSaveData keygen.LocalPartySaveData
	err := json.Unmarshal(data, &localSaveData)
	if err != nil {
		return nil, fmt.Errorf("failed deserializing shares: %w", err)
	}
	localSaveData.ECDSAPub.SetCurve(curveIdToCurve(curveId))
	for _, xj := range localSaveData.BigXj {
		xj.SetCurve(curveIdToCurve(curveId))
	}

	return &localSaveData, nil
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func keccak256(data []byte) []byte {

	prefix := "\x19Ethereum Signed Message:\n" + strconv.Itoa(len(data))
	msg := []byte(prefix + string(data))
	hash := crypto.Keccak256(msg)
	return hash
}
func verifySignature(hash []byte, signature []byte, pubKey []byte) bool {
	return crypto.VerifySignature(pubKey, hash, signature)
}
func ToEthereumSignature(r, s *big.Int) []byte {
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	sig := append(rPadded, sPadded...)
	return sig
}
func derivePublicKey(ec elliptic.Curve, key keygen.LocalPartySaveData, code []byte, hardened bool) (*keygen.LocalPartySaveData, *big.Int, error) {
	if !hardened {
		deltaInt := big.NewInt(0).SetBytes(code)
		gDelta := crypto_tss.ScalarBaseMult(ec, deltaInt)
		key1 := key
		newPk, err := key1.ECDSAPub.Add(gDelta)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating new extended child public key")
		}
		key1.ECDSAPub = newPk
		for j := range key1.BigXj {
			newXj, err := key1.BigXj[j].Add(gDelta)
			if err != nil {
				return nil, nil, fmt.Errorf("error in delta operation")
			}
			key1.BigXj[j] = newXj
		}
		return &key1, deltaInt, nil
	} else {
		key1 := key
		deltaInt, newPk, err := derivingPubkeyFromPath(key1.ECDSAPub, code, path, ec)
		if err != nil {
			return nil, nil, fmt.Errorf("error deriving pubkey from path")
		}
		pk, err := crypto_tss.NewECPoint(ec, newPk.X, newPk.Y)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating new extended child public key")
		}
		key1.ECDSAPub = pk
		gDelta := crypto_tss.ScalarBaseMult(ec, deltaInt)
		for j := range key1.BigXj {
			newXj, err := key1.BigXj[j].Add(gDelta)
			if err != nil {
				return nil, nil, fmt.Errorf("error in delta operation")
			}
			key1.BigXj[j] = newXj
		}
		return &key1, deltaInt, nil
	}
}

func derivingPubkeyFromPath(masterPub *crypto_tss.ECPoint, chainCode []byte, path []uint32, ec elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	pk := ecdsa.PublicKey{
		Curve: ec,
		X:     masterPub.X(),
		Y:     masterPub.Y(),
	}

	net := &chaincfg.MainNetParams
	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  pk,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode[:],
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    net.HDPrivateKeyID[:],
	}

	return ckd.DeriveChildKeyFromHierarchy(path, extendedParentPk, ec.Params().N, ec)
}

func ecPointToETHPubKey(ecPoint *crypto_tss.ECPoint) []byte {
	pk := ecPoint.ToECDSAPubKey()
	return crypto.FromECDSAPub(pk)
}
