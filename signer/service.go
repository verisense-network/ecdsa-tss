package signer

import (
	"bsctss/config"
	"bsctss/logger"
	pb "bsctss/signer/proto"
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SignerServer struct {
	pb.UnimplementedSignerServiceServer
}

func StartSignerServer(port uint16) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	grpcServer := grpc.NewServer()
	pb.RegisterSignerServiceServer(grpcServer, &SignerServer{})
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
		return nil
	}
	if err != nil {
		logger.Errorf("receive error: %v\n", err)
		return err
	}
	logger.Debugf("DKG request: %v", req)
	// req.ReqType must be "init"
	if req.ReqType != "init" {
		logger.Errorf("the first request from client must be init, but got %s", req.ReqType)
		return status.Error(codes.InvalidArgument, fmt.Sprintf("the first request from client must be init, but got %s", req.ReqType))
	}
	curveId, id, ids, threshold, err := checkBaseInfo(req.BaseInfo)
	if err != nil {
		logger.Errorf("invalid base info: %v", err)
		return err
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
		return status.Error(codes.Internal, fmt.Sprintf("failed to generate key: %v", err))
	}
	keyPackage, err := bytesToLocalPartySaveData(0, rawOut)
	if err != nil {
		logger.Errorf("failed to convert to local party save data: %v", err)
		return status.Error(codes.Internal, fmt.Sprintf("failed to convert to local party save data: %v", err))
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
func (s *SignerServer) Sign(stream pb.SignerService_SignServer) error {
	sessionID := uuid.New().String()
	logger := logger.Logger.With("session_id", sessionID)
	req, err := stream.Recv()
	if err == io.EOF {
		logger.Warn("client closed stream (EOF)")
		return nil
	}
	if err != nil {
		logger.Error("receive error: %v\n", err)
		return err
	}
	// req.ReqType must be "init"
	if req.ReqType != "init" {
		logger.Errorf("the first request from client must be init, but got %s", req.ReqType)
		return status.Error(codes.InvalidArgument, fmt.Sprintf("the first request from client must be init, but got %s", req.ReqType))
	}
	curveId, id, ids, threshold, err := checkBaseInfo(req.SigningInfo.BaseInfo)
	if err != nil {
		logger.Errorf("invalid base info: %v", err)
		return err
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(config.Config().SigningTimeout))
	defer cancel()
	in := make(chan *pb.CoordinatorToSignerMsg, 1000)
	go listenSignCoordinatorToSignerMsg(stream, in, logger)
	signature, err := signerSign(ctx, curveId, id, ids, threshold-1, req.SigningInfo.Message, req.SigningInfo.KeyPackage.KeyPackage, req.SigningInfo.DerivationDelta, func(msg []byte, isBroadcast bool, to uint16) error {
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
		return status.Error(codes.Internal, fmt.Sprintf("failed to sign: %v", err))
	}
	resp := &pb.SignResponse{
		RespType:  "final",
		Signature: signature,
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
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(config.Config().SigningTimeout))
	defer cancel()
	localPartySaveData, _, err := signerDeriveKeyPackage(ctx, curveId, req.KeyPackage.KeyPackage, req.DerivationDelta, logger)
	if err != nil {
		logger.Errorf("failed to convert to local party save data: %v", err)
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to convert to local party save data: %v", err))
	}
	pk := localPartySaveData.ECDSAPub.ToECDSAPubKey()
	pkBytes := crypto.FromECDSAPub(pk)
	return &pb.PkResponse{
		PublicKey: pkBytes,
	}, nil
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
