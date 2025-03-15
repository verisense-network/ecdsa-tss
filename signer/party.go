package signer

import (
	"bsctss/config"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	pb "bsctss/signer/proto"

	"github.com/bnb-chain/tss-lib/v2/common"
	crypto_tss "github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"go.uber.org/zap"
)

func signerDKG(ctx context.Context, curveId uint16, id uint16, parties []uint16, threshold uint16, sendMsgAsync func(msg []byte, isBroadcast bool, to uint16) error, in chan *pb.CoordinatorToSignerMsg, logger *zap.SugaredLogger) ([]byte, error) {
	logger.Infof("start dkg with id: %d, parties: %v, threshold: %d", id, parties, threshold)
	partyIDs := numbersToPartyIDs(parties)
	tssCtx := tss.NewPeerContext(partyIDs)
	curve := curveIdToCurve(curveId)
	pid := numberToPartyID(id)
	params := tss.NewParameters(curve, tssCtx, pid, len(parties), int(threshold))
	pid.Index = locatePartyIndex(params, pid)

	preParamGenTimeout := config.Config().SafePrimeGenTimeout
	deadline, deadlineExists := ctx.Deadline()
	if deadlineExists {
		preParamGenTimeout = time.Until(deadline)
	}
	logger.Infof("preParamGenTimeout: %s", preParamGenTimeout)
	preParams, err := keygen.GeneratePreParams(preParamGenTimeout)
	if err != nil {
		logger.Errorf("failed to generate pre params: %s", err)
		return nil, err
	}
	// four rounds
	out := make(chan tss.Message, 100)
	end := make(chan *keygen.LocalPartySaveData, 1)
	party := keygen.NewLocalParty(params, out, end, *preParams)

	var endWG sync.WaitGroup
	endWG.Add(1)
	errChan := make(chan error, 1)
	go func() {
		defer endWG.Done()
		err := party.Start()
		if err != nil {
			logger.Errorf("Failed generating key: %v", err)
			errChan <- err
		}
	}()

	defer endWG.Wait()
	dkgRawOut := []byte{}
	endProcessed := false
	for {
		if endProcessed && len(out) == 0 && len(in) == 0 {
			return dkgRawOut, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("DKG timed out: %w", ctx.Err())
		case err := <-errChan:
			return nil, fmt.Errorf("failed generating key: %w", err)
		case dkgOut := <-end:
			dkgRawOut, err = json.Marshal(*dkgOut)
			if err != nil {
				return nil, fmt.Errorf("failed serializing DKG output: %w", err)
			}
			endProcessed = true
		case msg := <-out:
			msgBytes, routing, err := msg.WireBytes()
			if err != nil {
				logger.Errorf("Failed marshaling message: %v", err)
				return nil, fmt.Errorf("failed marshaling message: %w", err)
			}
			if routing.IsBroadcast {
				err := sendMsgAsync(msgBytes, routing.IsBroadcast, 0)
				if err != nil {
					logger.Errorf("Failed sending broadcast message: %v", err)
					return nil, fmt.Errorf("failed sending broadcast message: %w", err)
				}
			} else {
				for _, to := range msg.GetTo() {
					err := sendMsgAsync(msgBytes, routing.IsBroadcast, uint16(big.NewInt(0).SetBytes(to.Key).Uint64()))
					if err != nil {
						logger.Errorf("Failed sending message to %s: %v", to.Id, err)
						return nil, fmt.Errorf("failed sending message to %s: %w", to.Id, err)
					}
				}
			}

		case msg := <-in:
			logger.Debugf("node %d received message from %d, %v", id, msg.From, msg.IsBroadcast)
			id := tss.NewPartyID(fmt.Sprintf("%d", msg.From), "", big.NewInt(int64(msg.From)))
			id.Index = locatePartyIndex(params, id)
			parsed_msg, err := tss.ParseWireMessage(msg.Msg, id, msg.IsBroadcast)
			if err != nil {
				logger.Warnf("Received invalid message (%s) of %d bytes from %d: %v", base64.StdEncoding.EncodeToString(msg.Msg), len(msg.Msg), msg.From, err)
				continue
			}

			key := parsed_msg.GetFrom().KeyInt()
			if key == nil || key.Cmp(big.NewInt(int64(math.MaxUint16))) >= 0 {
				logger.Warnf("Message received from invalid key: %v", key)
				continue
			}

			claimedFrom := uint16(key.Uint64())
			if claimedFrom != uint16(msg.From) {
				logger.Warnf("Message claimed to be from %d but was received from %d", claimedFrom, msg.From)
				continue
			}
			raw, routing, err := parsed_msg.WireBytes()
			if err != nil {
				logger.Warnf("Received error when serializing message: %v", err)
				continue
			}
			logger.Debugf("%s Got message from %s", pid.Id, routing.From.Id)
			ok, err := party.UpdateFromBytes(raw, routing.From, routing.IsBroadcast)
			if !ok {
				logger.Warnf("Received error when updating party: %v", err.Error())
				continue
			}
		}
	}

}

func signerDeriveKeyPackageAndUpdateShamirShares(curveId uint16, keyPackage []byte, derivationDelta []byte, logger *zap.SugaredLogger) (*keygen.LocalPartySaveData, *keygen.LocalPartySaveData, *big.Int, error) {
	curve := curveIdToCurve(curveId)
	localPartySaveData, err := bytesToLocalPartySaveData(curveId, keyPackage)
	if err != nil {
		logger.Errorf("failed to convert to local party save data: %v", err)
		return nil, nil, nil, err
	}
	hash := sha256.Sum256(derivationDelta)
	derivedKeyPackage, deltaInt, err := derivePublicKeyAndUpdateShamirShares(curve, *localPartySaveData, hash[:], true)
	if err != nil {
		logger.Errorf("failed to derive public key: %v", err)
		return nil, nil, nil, err
	}
	return localPartySaveData, derivedKeyPackage, deltaInt, nil
}
func signerDerivePublicKey(curveId uint16, publicKey []byte, derivationDelta []byte, logger *zap.SugaredLogger) (*crypto_tss.ECPoint, *big.Int, error) {
	curve := curveIdToCurve(curveId)
	pk, err := ETHPubKeyToECPoint(publicKey)
	if err != nil {
		logger.Errorf("failed to convert to ec point: %v", err)
		return nil, nil, err
	}
	hash := sha256.Sum256(derivationDelta)
	derivedPk, deltaInt, err := derivePublicKeyPk(curve, pk, hash[:], true)
	if err != nil {
		logger.Errorf("failed to derive public key: %v", err)
		return nil, nil, err
	}
	return derivedPk, deltaInt, nil
}

func signerSign(ctx context.Context, curveId uint16, id uint16, parties []uint16, threshold uint16, message []byte, keyPackage []byte, derivationDelta []byte, sendMsgAsync func(msg []byte, isBroadcast bool, to uint16) error, in chan *pb.CoordinatorToSignerMsg, logger *zap.SugaredLogger) ([]byte, []byte, []byte, error) {
	// if len(message) != 32 {
	// 	return nil, nil, nil, fmt.Errorf("message must be 32 bytes")
	// }
	logger.Infof("start sign with id: %d, parties: %v, threshold: %d", id, parties, threshold)
	partyIDs := numbersToPartyIDs(parties)
	tssCtx := tss.NewPeerContext(partyIDs)
	curve := curveIdToCurve(curveId)
	pid := numberToPartyID(id)
	params := tss.NewParameters(curve, tssCtx, pid, len(parties), int(threshold))
	pid.Index = locatePartyIndex(params, pid)
	keyPackageOriginal, keyPackageDerived, deltaInt, err := signerDeriveKeyPackageAndUpdateShamirShares(curveId, keyPackage, derivationDelta, logger)
	if err != nil {
		logger.Errorf("failed to derive key package: %v", err)
		return nil, nil, nil, err
	}
	publicKeyDerived := ecPointToETHPubKey(keyPackageDerived.ECDSAPub)
	publicKey := ecPointToETHPubKey(keyPackageOriginal.ECDSAPub)
	out := make(chan tss.Message, 100)
	end := make(chan *common.SignatureData, 1)
	msgToSign := hashToInt(message, curve)
	// nine rounds
	party := signing.NewLocalPartyWithKDD(msgToSign, params, *keyPackageDerived, deltaInt, out, end)

	var endWG sync.WaitGroup
	endWG.Add(1)
	errChan := make(chan error, 1)
	go func() {
		defer endWG.Done()
		err := party.Start()
		if err != nil {
			logger.Errorf("Failed signing: %v", err)
			errChan <- err
		}
	}()

	defer endWG.Wait()
	endProcessed := false
	sigRaw := []byte{}
	for {
		if endProcessed && len(out) == 0 && len(in) == 0 {
			return sigRaw, publicKey, publicKeyDerived, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, nil, fmt.Errorf("signing timed out: %w", ctx.Err())
		case err := <-errChan:
			return nil, nil, nil, fmt.Errorf("failed signing: %w", err)
		case sigOut := <-end:
			if !bytes.Equal(sigOut.M, message) {
				return nil, nil, nil, fmt.Errorf("message we requested to sign is %s but actual message signed is %s",
					base64.StdEncoding.EncodeToString(msgToSign.Bytes()),
					base64.StdEncoding.EncodeToString(sigOut.M))
			}
			var sig struct {
				R, S *big.Int
			}
			sig.R = big.NewInt(0)
			sig.S = big.NewInt(0)
			sig.R.SetBytes(sigOut.R)
			sig.S.SetBytes(sigOut.S)
			sigRaw = ToEthereumSignature(sig.R, sig.S)
			endProcessed = true
		case msg := <-out:
			msgBytes, routing, err := msg.WireBytes()
			if err != nil {
				logger.Errorf("Failed marshaling message: %v", err)
				return nil, nil, nil, fmt.Errorf("failed marshaling message: %w", err)
			}
			if routing.IsBroadcast {
				err := sendMsgAsync(msgBytes, routing.IsBroadcast, 0)
				if err != nil {
					logger.Errorf("Failed sending broadcast message: %v", err)
					return nil, nil, nil, fmt.Errorf("failed sending broadcast message: %w", err)
				}
			} else {
				for _, to := range msg.GetTo() {
					err := sendMsgAsync(msgBytes, routing.IsBroadcast, uint16(big.NewInt(0).SetBytes(to.Key).Uint64()))
					if err != nil {
						logger.Errorf("Failed sending message to %s: %v", to.Id, err)
						return nil, nil, nil, fmt.Errorf("failed sending message to %s: %w", to.Id, err)
					}
				}
			}

		case msg := <-in:
			logger.Debugf("node %d received message from %d, %v", id, msg.From, msg.IsBroadcast)
			id := tss.NewPartyID(fmt.Sprintf("%d", msg.From), "", big.NewInt(int64(msg.From)))
			id.Index = locatePartyIndex(params, id)
			parsed_msg, err := tss.ParseWireMessage(msg.Msg, id, msg.IsBroadcast)
			if err != nil {
				logger.Warnf("Received invalid message (%s) of %d bytes from %d: %v", base64.StdEncoding.EncodeToString(msg.Msg), len(msg.Msg), msg.From, err)
				continue
			}

			key := parsed_msg.GetFrom().KeyInt()
			if key == nil || key.Cmp(big.NewInt(int64(math.MaxUint16))) >= 0 {
				logger.Warnf("Message received from invalid key: %v", key)
				continue
			}

			claimedFrom := uint16(key.Uint64())
			if claimedFrom != uint16(msg.From) {
				logger.Warnf("Message claimed to be from %d but was received from %d", claimedFrom, msg.From)
				continue
			}
			raw, routing, err := parsed_msg.WireBytes()
			if err != nil {
				logger.Warnf("Received error when serializing message: %v", err)
				continue
			}
			logger.Debugf("%s Got message from %s", pid.Id, routing.From.Id)
			ok, err := party.UpdateFromBytes(raw, routing.From, routing.IsBroadcast)
			if !ok {
				logger.Warnf("Received error when updating party: %v", err.Error())
				continue
			}
		}
	}

}
