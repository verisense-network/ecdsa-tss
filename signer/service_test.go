package signer

import (
	"context"
	"crypto/sha256"
	"strconv"
	"testing"

	pb "bsctss/signer/proto"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestErrorDKG(t *testing.T) {
	go StartSignerServer(15289)

	conn, err := grpc.NewClient("localhost:15289",
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewSignerServiceClient(conn)

	stream, err := client.DKG(context.Background())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer stream.CloseSend()

	req := &pb.DKGRequest{
		ReqType: "error",
	}
	if err := stream.Send(req); err != nil {
		t.Fatalf("send error: %v", err)
	}

	resp, err := stream.Recv()
	assert.EqualError(t, err, "rpc error: code = InvalidArgument desc = the first request from client must be init, but got error")
	assert.Nil(t, resp)
}
func singleNode(ctx context.Context, t *testing.T, port uint16, id uint32, in chan *pb.DKGRequest, out chan *pb.DKGResponse, end chan error, key chan []byte) {
	go StartSignerServer(port)
	conn, err := grpc.NewClient("localhost:"+strconv.Itoa(int(port)),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Errorf("recv error: %v", err)
		end <- err
		return
	}
	defer conn.Close()

	client := pb.NewSignerServiceClient(conn)

	stream, err := client.DKG(context.Background())
	if err != nil {
		t.Errorf("recv error: %v", err)
		end <- err
		return
	}
	defer stream.CloseSend()

	req := &pb.DKGRequest{
		ReqType: "init",
		BaseInfo: &pb.BaseInfo{
			CurveId:   0,
			Id:        id,
			Threshold: 2,
			Ids:       []uint32{1, 2, 3},
		},
	}
	if err := stream.Send(req); err != nil {
		end <- err
		return
	}
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				t.Errorf("recv error: %v", err)
				end <- err
				return
			}
			if resp.RespType == "final" {
				key <- resp.KeyPackage.KeyPackage
				return
			}
			out <- resp
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-in:
			if err := stream.Send(req); err != nil {
				t.Errorf("recv error: %v", err)
				end <- err
				return
			}
		}
	}
}
func handleOut(out *pb.SignerToCoordinatorMsg, id uint32, in1, in2, in3 chan *pb.DKGRequest) {
	msg := &pb.CoordinatorToSignerMsg{
		Msg:         out.Msg,
		IsBroadcast: out.IsBroadcast,
		From:        id,
	}
	if out.IsBroadcast {
		if id != 1 {
			in1 <- &pb.DKGRequest{
				ReqType:                "intermediate",
				CoordinatorToSignerMsg: msg,
			}
		}
		if out.To != 2 {
			in2 <- &pb.DKGRequest{
				ReqType:                "intermediate",
				CoordinatorToSignerMsg: msg,
			}
		}
		if out.To != 3 {
			in3 <- &pb.DKGRequest{
				ReqType:                "intermediate",
				CoordinatorToSignerMsg: msg,
			}
		}
	} else {
		switch out.To {
		case 1:
			in1 <- &pb.DKGRequest{
				ReqType:                "intermediate",
				CoordinatorToSignerMsg: msg,
			}
		case 2:
			in2 <- &pb.DKGRequest{
				ReqType:                "intermediate",
				CoordinatorToSignerMsg: msg,
			}
		case 3:
			in3 <- &pb.DKGRequest{
				ReqType:                "intermediate",
				CoordinatorToSignerMsg: msg,
			}
		}
	}
}
func TestDKG(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in1 := make(chan *pb.DKGRequest, 1000)
	out1 := make(chan *pb.DKGResponse, 1000)
	end1 := make(chan error)
	key1 := make(chan []byte)
	go singleNode(ctx, t, 15200, 1, in1, out1, end1, key1)

	in2 := make(chan *pb.DKGRequest, 1000)
	out2 := make(chan *pb.DKGResponse, 1000)
	end2 := make(chan error)
	key2 := make(chan []byte)
	go singleNode(ctx, t, 15201, 2, in2, out2, end2, key2)

	in3 := make(chan *pb.DKGRequest, 1000)
	out3 := make(chan *pb.DKGResponse, 1000)
	end3 := make(chan error)
	key3 := make(chan []byte)
	go singleNode(ctx, t, 15202, 3, in3, out3, end3, key3)
	total := 0
	for {
		select {
		case err := <-end1:
			t.Fatalf("end1: %v", err)
		case err := <-end2:
			t.Fatalf("end2: %v", err)
		case err := <-end3:
			t.Fatalf("end3: %v", err)
		case key := <-key1:
			hash := sha256.Sum256(key)
			t.Logf("key1: %v", hash)
			total++
		case key := <-key2:
			hash := sha256.Sum256(key)
			t.Logf("key2: %v", hash)
			total++
		case key := <-key3:
			hash := sha256.Sum256(key)
			t.Logf("key3: %v", hash)
			total++
		case out := <-out1:
			handleOut(out.SignerToCoordinatorMsg, 1, in1, in2, in3)
		case out := <-out2:
			handleOut(out.SignerToCoordinatorMsg, 2, in1, in2, in3)
		case out := <-out3:
			handleOut(out.SignerToCoordinatorMsg, 3, in1, in2, in3)
		}
		if total == 3 {
			break
		}
	}
}
