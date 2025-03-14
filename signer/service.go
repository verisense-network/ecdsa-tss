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
	return grpcServer.Serve(lis)
}

func (s *SignerServer) DKG(stream pb.SignerService_DKGServer) error {
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
	if req.BaseInfo.CurveId > 1 {
		logger.Errorf("curve_id must be 0 or 1, but got %d", req.BaseInfo.CurveId)
		return status.Error(codes.InvalidArgument, fmt.Sprintf("curve_id must be 0 or 1, but got %d", req.BaseInfo.CurveId))
	}
	// check id in ids
	if !slices.Contains(req.BaseInfo.Ids, req.BaseInfo.Id) {
		logger.Errorf("id must be in ids, but got %d", req.BaseInfo.Id)
		return status.Error(codes.InvalidArgument, fmt.Sprintf("id must be in ids, but got %d", req.BaseInfo.Id))
	}
	// check threshold
	if req.BaseInfo.Threshold > uint32(len(req.BaseInfo.Ids)) {
		logger.Errorf("threshold must be less than or equal to the number of ids, but got %d", req.BaseInfo.Threshold)
		return status.Error(codes.InvalidArgument, fmt.Sprintf("threshold must be less than or equal to the number of ids, but got %d", req.BaseInfo.Threshold))
	}
	if req.BaseInfo.Threshold == 0 {
		logger.Errorf("threshold must be greater than 0, but got %d", req.BaseInfo.Threshold)
		return status.Error(codes.InvalidArgument, fmt.Sprintf("threshold must be greater than 0, but got %d", req.BaseInfo.Threshold))
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(config.Config().DKGTimeout))
	defer cancel()
	in := make(chan *pb.CoordinatorToSignerMsg, 1000)
	go listenCoordinatorToSignerMsg(stream, in, logger)
	curveId, err := convertU32ToU16(req.BaseInfo.CurveId)
	if err != nil {
		logger.Errorf("invalid curve_id: %v", err)
		return status.Error(codes.InvalidArgument, fmt.Sprintf("invalid curve_id: %v", err))
	}
	id, err := convertU32ToU16(req.BaseInfo.Id)
	if err != nil {
		logger.Errorf("invalid id: %v", err)
		return status.Error(codes.InvalidArgument, fmt.Sprintf("invalid id: %v", err))
	}
	threshold, err := convertU32ToU16(req.BaseInfo.Threshold)
	if err != nil {
		logger.Errorf("invalid threshold: %v", err)
		return status.Error(codes.InvalidArgument, fmt.Sprintf("invalid threshold: %v", err))
	}
	ids := make([]uint16, len(req.BaseInfo.Ids))
	for i, ii := range req.BaseInfo.Ids {
		ids[i], err = convertU32ToU16(ii)
		if err != nil {
			logger.Errorf("invalid id: %v", err)
			return status.Error(codes.InvalidArgument, fmt.Sprintf("invalid id: %v", err))
		}
	}
	rawOut, err := signerDKG(ctx, curveId, id, ids, threshold-1, func(msg []byte, isBroadcast bool, to uint16) error {
		logger.Infof("DKG stream started for session %s with req %v", sessionID, req)
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
	resp := &pb.DKGResponse{
		RespType: "final",
		KeyPackage: &pb.KeyPackage{
			KeyPackage: rawOut,
		},
	}
	return stream.Send(resp)
}
func listenCoordinatorToSignerMsg(stream pb.SignerService_DKGServer, in chan *pb.CoordinatorToSignerMsg, logger *zap.SugaredLogger) {
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
