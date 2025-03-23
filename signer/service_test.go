package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"strconv"
	"testing"
	"time"

	pb "ecdsa-tss/signer/proto"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

//go:embed testdata/key1.json
var key1 string

//go:embed testdata/key2.json
var key2 string

//go:embed testdata/key3.json
var key3 string

const threshold = 2

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
func singleNodeDKG(ctx context.Context, t *testing.T, port uint16, id uint32, in chan *pb.DKGRequest, out chan *pb.DKGResponse, end chan error, key chan *pb.KeyPackage) {
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
	// calc time
	start := time.Now()
	stream, err := client.DKG(context.Background())
	elapsed := time.Since(start)
	t.Logf("time: %v", elapsed)
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
			Threshold: threshold,
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
			if resp.RespType == "empty" {
				continue
			}
			if resp.RespType == "final" {
				key <- resp.KeyPackage
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
func singleNodeSign(ctx context.Context, t *testing.T, port uint16, id uint32, in chan *pb.SignRequest, out chan *pb.SignResponse, end chan error, signature chan []byte) {
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

	stream, err := client.Sign(context.Background())
	if err != nil {
		t.Errorf("recv error: %v", err)
		end <- err
		return
	}
	defer stream.CloseSend()
	var keyPackage []byte
	switch id {
	case 1:
		keyPackage = []byte(key1)
	case 2:
		keyPackage = []byte(key2)
	case 3:
		keyPackage = []byte(key3)
	}
	fmt.Println("id: ", id)
	req := &pb.SignRequest{
		ReqType: "init",
		SigningInfo: &pb.SigningInfo{
			BaseInfo: &pb.BaseInfo{
				CurveId:   0,
				Id:        id,
				Threshold: threshold,
				Ids:       []uint32{1, 2},
			},
			Message:         keccak256([]byte("test")),
			KeyPackage:      &pb.KeyPackage{KeyPackage: keyPackage},
			DerivationDelta: []byte{1, 2, 3, 4},
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
			if resp.RespType == "empty" {
				continue
			}
			if resp.RespType == "final" {
				signature <- resp.Signature.Signature
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
func handleSignOut(out *pb.SignerToCoordinatorMsg, id uint32, in1, in2 chan *pb.SignRequest) {
	msg := &pb.CoordinatorToSignerMsg{
		Msg:         out.Msg,
		IsBroadcast: out.IsBroadcast,
		From:        id,
	}
	if out.IsBroadcast {
		if id != 1 {
			in1 <- &pb.SignRequest{
				ReqType:                "intermediate",
				CoordinatorToSignerMsg: msg,
			}
		}
		if id != 2 {
			in2 <- &pb.SignRequest{
				ReqType:                "intermediate",
				CoordinatorToSignerMsg: msg,
			}
		}
	} else {
		switch out.To {
		case 1:
			in1 <- &pb.SignRequest{
				ReqType:                "intermediate",
				CoordinatorToSignerMsg: msg,
			}
		case 2:
			in2 <- &pb.SignRequest{
				ReqType:                "intermediate",
				CoordinatorToSignerMsg: msg,
			}
		}
	}
}
func handleDKGOut(out *pb.SignerToCoordinatorMsg, id uint32, in1, in2, in3 chan *pb.DKGRequest) {
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
	key1 := make(chan *pb.KeyPackage)
	go singleNodeDKG(ctx, t, 15200, 1, in1, out1, end1, key1)

	in2 := make(chan *pb.DKGRequest, 1000)
	out2 := make(chan *pb.DKGResponse, 1000)
	end2 := make(chan error)
	key2 := make(chan *pb.KeyPackage)
	go singleNodeDKG(ctx, t, 15201, 2, in2, out2, end2, key2)

	in3 := make(chan *pb.DKGRequest, 1000)
	out3 := make(chan *pb.DKGResponse, 1000)
	end3 := make(chan error)
	key3 := make(chan *pb.KeyPackage)
	go singleNodeDKG(ctx, t, 15202, 3, in3, out3, end3, key3)
	total := 0
	k := []byte{}
	for {
		select {
		case err := <-end1:
			t.Fatalf("end1: %v", err)
		case err := <-end2:
			t.Fatalf("end2: %v", err)
		case err := <-end3:
			t.Fatalf("end3: %v", err)
		case key := <-key1:
			hash := sha256.Sum256(key.KeyPackage)
			t.Logf("key1: %v ,pk: %x", hash, key.PublicKey)
			assert.True(t, bytes.Equal(k, key.PublicKey) || bytes.Equal(k, []byte{}))
			k = key.PublicKey
			// os.MkdirAll("testdata", 0755)
			// os.WriteFile("testdata/key1.json", key.KeyPackage, 0644)
			total++
		case key := <-key2:
			hash := sha256.Sum256(key.KeyPackage)
			t.Logf("key2: %v ,pk: %x", hash, key.PublicKey)
			assert.True(t, bytes.Equal(k, key.PublicKey) || bytes.Equal(k, []byte{}))
			k = key.PublicKey
			// os.MkdirAll("testdata", 0755)
			// os.WriteFile("testdata/key2.json", key.KeyPackage, 0644)
			total++
		case key := <-key3:
			hash := sha256.Sum256(key.KeyPackage)
			t.Logf("key3: %v ,pk: %x", hash, key.PublicKey)
			assert.True(t, bytes.Equal(k, key.PublicKey) || bytes.Equal(k, []byte{}))
			k = key.PublicKey
			// os.MkdirAll("testdata", 0755)
			// os.WriteFile("testdata/key3.json", key.KeyPackage, 0644)
			total++
		case out := <-out1:
			handleDKGOut(out.SignerToCoordinatorMsg, 1, in1, in2, in3)
		case out := <-out2:
			handleDKGOut(out.SignerToCoordinatorMsg, 2, in1, in2, in3)
		case out := <-out3:
			handleDKGOut(out.SignerToCoordinatorMsg, 3, in1, in2, in3)
		}
		if total == 3 {
			break
		}
	}
}

func TestSign(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in1 := make(chan *pb.SignRequest, 1000)
	out1 := make(chan *pb.SignResponse, 1000)
	end1 := make(chan error)
	signature1 := make(chan []byte)
	go singleNodeSign(ctx, t, 15200, 1, in1, out1, end1, signature1)

	in2 := make(chan *pb.SignRequest, 1000)
	out2 := make(chan *pb.SignResponse, 1000)
	end2 := make(chan error)
	signature2 := make(chan []byte)
	go singleNodeSign(ctx, t, 15201, 2, in2, out2, end2, signature2)

	// in3 := make(chan *pb.SignRequest, 1000)
	// out3 := make(chan *pb.SignResponse, 1000)
	// end3 := make(chan error)
	// signature3 := make(chan []byte)
	// go singleNodeSign(ctx, t, 15202, 3, in3, out3, end3, signature3)
	total := 0
	sig := []byte{}
	for {
		select {
		case err := <-end1:
			t.Fatalf("end1: %v", err)
		case err := <-end2:
			t.Fatalf("end2: %v", err)
		// case err := <-end3:
		// 	t.Fatalf("end3: %v", err)
		case signature := <-signature1:
			t.Logf("signature1: %x", signature)
			assert.True(t, bytes.Equal(sig, signature) || bytes.Equal(sig, []byte{}))
			sig = signature
			total++
		case signature := <-signature2:
			t.Logf("signature2: %x", signature)
			assert.True(t, bytes.Equal(sig, signature) || bytes.Equal(sig, []byte{}))
			sig = signature
			total++
		// case signature := <-signature3:
		// 	t.Logf("signature3: %x", signature)
		// 	assert.True(t, bytes.Equal(sig, signature) || bytes.Equal(sig, []byte{}))
		// 	sig = signature
		// 	total++
		case out := <-out1:
			handleSignOut(out.SignerToCoordinatorMsg, 1, in1, in2)
		case out := <-out2:
			handleSignOut(out.SignerToCoordinatorMsg, 2, in1, in2)
			// case out := <-out3:
			// 	handleSignOut(out.SignerToCoordinatorMsg, 3, in1, in2, in3)
			// }
		}
		if total == 2 {
			break
		}
	}
	go StartSignerServer(15203)
	conn, err := grpc.NewClient("localhost:"+strconv.Itoa(int(15203)),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("recv error: %v", err)
	}
	defer conn.Close()

	client := pb.NewSignerServiceClient(conn)
	resp, err := client.Pk(context.Background(), &pb.PkRequest{
		CurveId:         0,
		Source:          &pb.PkRequest_KeyPackage{KeyPackage: &pb.KeyPackage{KeyPackage: []byte(key2)}},
		DerivationDelta: []byte{1, 2, 3, 4},
	})

	if err != nil {
		t.Fatalf("recv error: %v", err)
	}
	assert.True(t, verifySignature(keccak256([]byte("test")), sig, resp.PublicKeyDerived))
	respCopy := resp
	client = pb.NewSignerServiceClient(conn)
	resp, err = client.Pk(context.Background(), &pb.PkRequest{
		CurveId:         0,
		Source:          &pb.PkRequest_PublicKey{PublicKey: resp.PublicKey},
		DerivationDelta: []byte{1, 2, 3, 4},
	})

	if err != nil {
		t.Fatalf("recv error: %v", err)
	}
	assert.Equal(t, respCopy, resp)
	assert.True(t, verifySignature(keccak256([]byte("test")), sig, resp.PublicKeyDerived))
}
