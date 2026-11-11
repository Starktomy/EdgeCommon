package pb_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

func TestLegacyNodeStreamWireCompatibility(t *testing.T) {
	// Existing field numbers, including an unknown future field (100), are
	// pinned independently of generated code and must survive a round trip.
	wire, err := hex.DecodeString("08071009180a220470696e672a027b7d30013a026f6ba00601")
	if err != nil {
		t.Fatal(err)
	}
	var message pb.NodeStreamMessage
	if err := proto.Unmarshal(wire, &message); err != nil {
		t.Fatal(err)
	}
	if message.NodeId != 7 || message.RequestId != 9 || message.TimeoutSeconds != 10 ||
		message.Code != "ping" || string(message.DataJSON) != "{}" || !message.IsOk || message.Message != "ok" {
		t.Fatal("legacy node-stream wire fields changed")
	}
	roundtrip, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, roundtrip) {
		t.Fatal("node-stream wire bytes or unknown fields changed")
	}
}

type compatibilityNodeServer struct {
	pb.UnimplementedNodeServiceServer
}

func (*compatibilityNodeServer) SendCommandToNode(_ context.Context, message *pb.NodeStreamMessage) (*pb.NodeStreamMessage, error) {
	return message, nil
}

func (*compatibilityNodeServer) NodeStream(stream pb.NodeService_NodeStreamServer) error {
	for {
		message, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(message); err != nil {
			return err
		}
	}
}

func TestGeneratedNodeRPCCompatibility(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	pb.RegisterNodeServiceServer(server, &compatibilityNodeServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	t.Cleanup(func() { _ = listener.Close() })
	connection, err := grpc.NewClient("passthrough:///node-compatibility",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := pb.NewNodeServiceClient(connection)
	input := &pb.NodeStreamMessage{NodeId: 9007199254740993, RequestId: 99, Code: "config", DataJSON: []byte(`{"version":7}`)}
	input.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	output, err := client.SendCommandToNode(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(input, output) {
		t.Fatal("generated unary RPC lost payload fields")
	}
	stream, err := client.NodeStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(input); err != nil {
		t.Fatal(err)
	}
	output, err = stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(input, output) {
		t.Fatal("generated bidirectional RPC lost payload fields")
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("stream completion = %v, want EOF", err)
	}
}
