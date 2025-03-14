package signer

import (
	"bsctss/config"
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	pb "bsctss/signer/proto"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"go.uber.org/zap"
)

func signerDKG(ctx context.Context, curveId uint16, id uint16, parties []uint16, threshold uint16, sendMsgAsync func(msg []byte, isBroadcast bool, to uint16) error, in chan *pb.CoordinatorToSignerMsg, logger *zap.SugaredLogger) ([]byte, error) {
	logger.Infof("start dkg with %d, %v, %d", id, parties, threshold)
	partyIDs := numbersToPartyIDs(parties)
	tssCtx := tss.NewPeerContext(partyIDs)
	var curve elliptic.Curve
	if curveId == 0 {
		curve = tss.S256()
	} else {
		curve = tss.Edwards()
	}
	pid := numberToPartyID(id)
	params := tss.NewParameters(curve, tssCtx, pid, len(parties), int(threshold))
	pid.Index = locatePartyIndex(partyIDs, pid)

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

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("DKG timed out: %w", ctx.Err())
		case err := <-errChan:
			return nil, fmt.Errorf("failed generating key: %w", err)
		case dkgOut := <-end:
			dkgRawOut, err := json.Marshal(*dkgOut)
			if err != nil {
				return nil, fmt.Errorf("failed serializing DKG output: %w", err)
			}
			return dkgRawOut, nil
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
			id.Index = locatePartyIndex(partyIDs, id)
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
