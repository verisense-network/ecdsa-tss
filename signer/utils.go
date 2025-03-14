package signer

import (
	"bytes"
	"fmt"
	"math"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

func numberToPartyID(number uint16) *tss.PartyID {
	return tss.NewPartyID(fmt.Sprintf("%d", number), "", big.NewInt(int64(number)))
}
func numbersToPartyIDs(numbers []uint16) []*tss.PartyID {
	var partyIDs []*tss.PartyID
	for _, number := range numbers {
		partyIDs = append(partyIDs, numberToPartyID(number))
	}
	return partyIDs
}

func locatePartyIndex(partyIDs []*tss.PartyID, id *tss.PartyID) int {
	for index, p := range partyIDs {
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
