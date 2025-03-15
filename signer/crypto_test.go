package signer

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

func TestETHPubKeyToECPoint(t *testing.T) {
	// generate a random pubkey
	privKey, err := crypto.GenerateKey()
	assert.NoError(t, err)
	pubKey := crypto.FromECDSAPub(&privKey.PublicKey)
	ecPoint, err := ETHPubKeyToECPoint(pubKey)
	assert.NoError(t, err)
	assert.Equal(t, pubKey, ecPointToETHPubKey(ecPoint))
}
