package signer

import (
	"bytes"
	"context"
	"ecdsa-tss/config"
	"ecdsa-tss/logger"
	pb "ecdsa-tss/signer/proto"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"time"

	crypto_tss "github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SignerServer struct {
	pb.UnimplementedSignerServiceServer
	db *bolt.DB
}

func StartSignerServer(port uint16) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	db, err := bolt.Open(config.Config().DBPath, 0600, nil)
	if err != nil {
		return err
	}
	defer db.Close()
	grpcServer := grpc.NewServer()
	pb.RegisterSignerServiceServer(grpcServer, &SignerServer{db: db})
	logger.Infof("Signer server started on port %d", port)
	return grpcServer.Serve(lis)
}

func checkBaseInfo(baseInfo *pb.BaseInfo) (curveId uint16, id uint16, ids []uint16, threshold uint16, err error) {
	if baseInfo.CurveId > 1 {
		logger.Errorf("curve_id must be 0 or 1, but got %d", baseInfo.CurveId)
		return 0, 0, nil, 0, status.Error(codes.InvalidArgument, fmt.Sprintf("curve_id must be 0 or 1, but got %d", baseInfo.CurveId))
	}
	// check id in ids
	if !slices.Contains(baseInfo.Ids, baseInfo.Id) {
		logger.Errorf("id must be in ids, but got %d", baseInfo.Id)
		return 0, 0, nil, 0, status.Error(codes.InvalidArgument, fmt.Sprintf("id must be in ids, but got %d", baseInfo.Id))
	}
	// check threshold
	if baseInfo.Threshold > uint32(len(baseInfo.Ids)) {
		logger.Errorf("threshold must be less than or equal to the number of ids, but got %d", baseInfo.Threshold)
		return 0, 0, nil, 0, status.Error(codes.InvalidArgument, fmt.Sprintf("threshold must be less than or equal to the number of ids, but got %d", baseInfo.Threshold))
	}
	if baseInfo.Threshold == 0 {
		logger.Errorf("threshold must be greater than 0, but got %d", baseInfo.Threshold)
		return 0, 0, nil, 0, status.Error(codes.InvalidArgument, fmt.Sprintf("threshold must be greater than 0, but got %d", baseInfo.Threshold))
	}
	curveId, err = convertU32ToU16(baseInfo.CurveId)
	if err != nil {
		logger.Errorf("invalid curve_id: %v", err)
		return 0, 0, nil, 0, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid curve_id: %v", err))
	}
	id, err = convertU32ToU16(baseInfo.Id)
	if err != nil {
		logger.Errorf("invalid id: %v", err)
		return 0, 0, nil, 0, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid id: %v", err))
	}
	threshold, err = convertU32ToU16(baseInfo.Threshold)
	if err != nil {
		logger.Errorf("invalid threshold: %v", err)
		return 0, 0, nil, 0, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid threshold: %v", err))
	}
	ids = make([]uint16, len(baseInfo.Ids))
	for i, ii := range baseInfo.Ids {
		ids[i], err = convertU32ToU16(ii)
		if err != nil {
			logger.Errorf("invalid id: %v", err)
			return 0, 0, nil, 0, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid id: %v", err))
		}
	}
	return curveId, id, ids, threshold, nil
}
func (s *SignerServer) DKG(stream pb.SignerService_DKGServer) error {
	sessionID := uuid.New().String()
	logger := logger.Logger.With("session_id", sessionID)
	logger.Info("DKG Started")
	stream.Send(&pb.DKGResponse{
		RespType: "empty",
	})
	req, err := stream.Recv()
	if err == io.EOF {
		logger.Warn("client closed stream (EOF)")
		return stream.Send(&pb.DKGResponse{
			RespType: "error",
			Error:    "client closed stream (EOF)",
		})
	}
	if err != nil {
		logger.Errorf("receive error: %v\n", err)
		return stream.Send(&pb.DKGResponse{
			RespType: "error",
			Error:    fmt.Sprintf("receive error: %v\n", err),
		})
	}
	logger.Debugf("DKG request: %v", req)
	// req.ReqType must be "init"
	if req.ReqType != "init" {
		logger.Errorf("the first request from client must be init, but got %s", req.ReqType)
		return stream.Send(&pb.DKGResponse{
			RespType: "error",
			Error:    fmt.Sprintf("the first request from client must be init, but got %s", req.ReqType),
		})
	}
	curveId, id, ids, threshold, err := checkBaseInfo(req.BaseInfo)
	if err != nil {
		logger.Errorf("invalid base info: %v", err)
		return stream.Send(&pb.DKGResponse{
			RespType: "error",
			Error:    fmt.Sprintf("invalid base info: %v", err),
		})
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(config.Config().DKGTimeout))
	defer cancel()
	in := make(chan *pb.CoordinatorToSignerMsg, 1000)
	go listenDKGCoordinatorToSignerMsg(stream, in, logger)
	rawOut, err := signerDKG(ctx, curveId, id, ids, threshold-1, func(msg []byte, isBroadcast bool, to uint16) error {
		// logger.Infof("DKG stream started for session %s with req %v", sessionID, req)
		resp := &pb.DKGResponse{
			RespType: "intermediate",
			SignerToCoordinatorMsg: &pb.SignerToCoordinatorMsg{
				Msg:         msg,
				IsBroadcast: isBroadcast,
				To:          uint32(to),
			},
		}
		if err := stream.Send(resp); err != nil {
			logger.Error("send error: %v\n", err)
			return err
		}
		return nil
	}, in, logger)
	if err != nil {
		logger.Errorf("failed to generate key: %v", err)
		return stream.Send(&pb.DKGResponse{
			RespType: "error",
			Error:    fmt.Sprintf("failed to generate key: %v", err),
		})
	}
	keyPackage, err := bytesToLocalPartySaveData(0, rawOut)
	if err != nil {
		logger.Errorf("failed to convert to local party save data: %v", err)
		return stream.Send(&pb.DKGResponse{
			RespType: "error",
			Error:    fmt.Sprintf("failed to convert to local party save data: %v", err),
		})
	}

	resp := &pb.DKGResponse{
		RespType: "final",
		KeyPackage: &pb.KeyPackage{
			KeyPackage: rawOut,
			PublicKey:  ecPointToETHPubKey(keyPackage.ECDSAPub),
		},
	}
	return stream.Send(resp)
}
func (s *SignerServer) CheckPk(ctx context.Context, req *pb.CheckPkRequest) (*pb.CheckPkResponse, error) {

	shares := make([]*keygen.LocalPartySaveData, len(req.PublicKeyInfo))
	deltaInt := big.NewInt(0)
	for i, pk := range req.PublicKeyInfo {
		var err error
		shares[i], err = bytesToLocalPartySaveData(0, pk)
		if err != nil {
			logger.Errorf("invalid public key info: %v", err)
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid public key info: %v", err))
		}
		_, _, delta, err := signerDeriveKeyPackageAndUpdateShamirShares(0, pk, req.Delta, logger.Logger)
		if err != nil {
			logger.Errorf("invalid public key info: %v", err)
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid public key info: %v", err))
		}
		if deltaInt.Cmp(delta) == 0 || deltaInt.Cmp(big.NewInt(0)) == 0 {
			deltaInt = delta
		} else {
			logger.Errorf("delta is not the same")
			return &pb.CheckPkResponse{
				IsValid: false,
			}, nil
		}
	}
	sk := ReconstructKey(shares)
	sk_derived := big.NewInt(0).Add(sk, deltaInt)
	sk_derived.Mod(sk_derived, tss.S256().Params().N)
	// check if secret is the private key of the public key
	pk := crypto_tss.ScalarBaseMult(tss.S256(), sk)
	pk_derived := crypto_tss.ScalarBaseMult(tss.S256(), sk_derived)
	pk_eth := ecPointToETHPubKey(pk)
	pk_derived_eth := ecPointToETHPubKey(pk_derived)
	if !bytes.Equal(req.PublicKey, pk_eth) || !bytes.Equal(req.PublicKeyDerived, pk_derived_eth) {
		logger.Errorf("public key is not the same")
		return &pb.CheckPkResponse{
			IsValid: false,
		}, nil
	}
	s.db.Update(func(tx *bolt.Tx) error {
		// pk_derived_eth as key, sk_derived as value
		bucket := tx.Bucket([]byte("pk"))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}
		// snapshot the db

		return bucket.Put([]byte(pk_derived_eth), sk_derived.Bytes())
	})
	return &pb.CheckPkResponse{
		IsValid: true,
	}, nil
}
func ReconstructKey(shares []*keygen.LocalPartySaveData) *big.Int {
	prime := tss.S256().Params().N
	secret := big.NewInt(0)
	for i, share := range shares {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j, other := range shares {
			if i == j {
				continue
			}
			temp := new(big.Int).Neg(other.ShareID)
			temp.Mod(temp, prime)
			num.Mul(num, temp).Mod(num, prime)
			temp = new(big.Int).Sub(share.ShareID, other.ShareID)
			temp.Mod(temp, prime)
			den.Mul(den, temp).Mod(den, prime)
		}
		lambda := new(big.Int).ModInverse(den, prime)
		lambda.Mul(lambda, num).Mod(lambda, prime)
		term := new(big.Int).Mul(share.Xi, lambda)
		secret.Add(secret, term).Mod(secret, prime)
	}
	return secret
}
func (s *SignerServer) Sign(stream pb.SignerService_SignServer) error {
	sessionID := uuid.New().String()
	logger := logger.Logger.With("session_id", sessionID)
	logger.Info("Signing Started")
	stream.Send(&pb.SignResponse{
		RespType: "empty",
	})
	req, err := stream.Recv()
	if err == io.EOF {
		logger.Warn("client closed stream (EOF)")
		return stream.Send(&pb.SignResponse{
			RespType: "error",
			Error:    "client closed stream (EOF)",
		})
	}
	if err != nil {
		logger.Error("receive error: %v\n", err)
		return stream.Send(&pb.SignResponse{
			RespType: "error",
			Error:    fmt.Sprintf("receive error: %v\n", err),
		})
	}
	// req.ReqType must be "init"
	if req.ReqType != "init" {
		logger.Errorf("the first request from client must be init, but got %s", req.ReqType)
		return stream.Send(&pb.SignResponse{
			RespType: "error",
			Error:    fmt.Sprintf("the first request from client must be init, but got %s", req.ReqType),
		})
	}
	curveId, id, ids, threshold, err := checkBaseInfo(req.SigningInfo.BaseInfo)
	if err != nil {
		logger.Errorf("invalid base info: %v", err)
		return stream.Send(&pb.SignResponse{
			RespType: "error",
			Error:    fmt.Sprintf("invalid base info: %v", err),
		})
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(config.Config().SigningTimeout))
	defer cancel()
	in := make(chan *pb.CoordinatorToSignerMsg, 1000)
	go listenSignCoordinatorToSignerMsg(stream, in, logger)
	signature, publicKey, publicKeyDerived, err := signerSign(ctx, curveId, id, ids, threshold-1, req.SigningInfo.Message, req.SigningInfo.KeyPackage.KeyPackage, req.SigningInfo.DerivationDelta, func(msg []byte, isBroadcast bool, to uint16) error {
		// logger.Infof("Signing stream started for session %s with req %v", sessionID, req)
		resp := &pb.SignResponse{
			RespType: "intermediate",
			SignerToCoordinatorMsg: &pb.SignerToCoordinatorMsg{
				Msg:         msg,
				IsBroadcast: isBroadcast,
				To:          uint32(to),
			},
		}
		if err := stream.Send(resp); err != nil {
			logger.Error("send error: %v\n", err)
			return err
		}
		return nil
	}, in, logger)
	if err != nil {
		logger.Errorf("failed to sign: %v", err)
		return stream.Send(&pb.SignResponse{
			RespType: "error",
			Error:    fmt.Sprintf("failed to sign: %v", err),
		})
	}
	resp := &pb.SignResponse{
		RespType:  "final",
		Signature: &pb.Signature{Signature: signature, PublicKey: publicKey, PublicKeyDerived: publicKeyDerived},
	}
	return stream.Send(resp)
}
func (s *SignerServer) Pk(ctx context.Context, req *pb.PkRequest) (*pb.PkResponse, error) {
	sessionID := uuid.New().String()
	logger := logger.Logger.With("session_id", sessionID)
	curveId, err := convertU32ToU16(req.CurveId)
	if err != nil {
		logger.Errorf("invalid curve_id: %v", err)
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid curve_id: %v", err))
	}
	if req.Source == nil {
		logger.Errorf("source is nil")
		return nil, status.Error(codes.InvalidArgument, "source is nil")
	}
	switch req.Source.(type) {
	case *pb.PkRequest_KeyPackage:
		// reflect req.Option
		keyPackage := req.Source.(*pb.PkRequest_KeyPackage).KeyPackage
		keyPackageOriginal, keyPackageDerived, _, err := signerDeriveKeyPackageAndUpdateShamirShares(curveId, keyPackage.KeyPackage, req.DerivationDelta, logger)
		if err != nil {
			logger.Errorf("failed to convert to local party save data: %v", err)
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to convert to local party save data: %v", err))
		}
		return &pb.PkResponse{
			PublicKey:        ecPointToETHPubKey(keyPackageOriginal.ECDSAPub),
			PublicKeyDerived: ecPointToETHPubKey(keyPackageDerived.ECDSAPub),
		}, nil
	case *pb.PkRequest_PublicKey:
		publicKey := req.Source.(*pb.PkRequest_PublicKey).PublicKey

		publicKeyDerived, _, err := signerDerivePublicKey(curveId, publicKey, req.DerivationDelta, logger)
		if err != nil {
			logger.Errorf("failed to derive public key: %v", err)
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to derive public key: %v", err))
		}
		return &pb.PkResponse{
			PublicKey:        publicKey,
			PublicKeyDerived: ecPointToETHPubKey(publicKeyDerived),
		}, nil
	}
	return nil, status.Error(codes.InvalidArgument, "invalid option")
}
func listenDKGCoordinatorToSignerMsg(stream pb.SignerService_DKGServer, in chan *pb.CoordinatorToSignerMsg, logger *zap.SugaredLogger) {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			logger.Warn("client closed stream (EOF)")
			return
		}
		if err != nil {
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.Canceled {
				logger.Info("stream canceled or context done, exiting...")
				return
			}
		}
		if err != nil {
			logger.Errorf("receive error: %v\n", err)
			continue
		}
		in <- msg.CoordinatorToSignerMsg
	}
}

func listenSignCoordinatorToSignerMsg(stream pb.SignerService_SignServer, in chan *pb.CoordinatorToSignerMsg, logger *zap.SugaredLogger) {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			logger.Warn("client closed stream (EOF)")
			return
		}
		if err != nil {
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.Canceled {
				logger.Info("stream canceled or context done, exiting...")
				return
			}
		}
		if err != nil {
			logger.Errorf("receive error: %v\n", err)
			continue
		}
		in <- msg.CoordinatorToSignerMsg
	}
}
