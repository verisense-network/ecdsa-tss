package signer

import (
	"bytes"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/ethereum/go-ethereum/crypto"
)

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
func bytesToLocalPartySaveData(curveId uint16, data []byte) (*keygen.LocalPartySaveData, []byte, error) {
	var localSaveData keygen.LocalPartySaveData
	err := json.Unmarshal(data, &localSaveData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed deserializing shares: %w", err)
	}
	localSaveData.ECDSAPub.SetCurve(curveIdToCurve(curveId))
	for _, xj := range localSaveData.BigXj {
		xj.SetCurve(curveIdToCurve(curveId))
	}
	pk := localSaveData.ECDSAPub.ToECDSAPubKey()

	pubBytes := crypto.FromECDSAPub(pk)

	return &localSaveData, pubBytes, nil
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

func hash(data []byte) []byte {

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
