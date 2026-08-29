// Package transport implements the versioned sensor ingestion stream. The
// protobuf wire structs are kept deliberately tiny so old spooled envelopes can
// be replayed by newer controllers.
package transport

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
)

const Version uint32 = 1

type Envelope struct {
	Version   uint32 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	SensorId  string `protobuf:"bytes,2,opt,name=sensor_id,json=sensorId,proto3" json:"sensor_id,omitempty"`
	MessageId string `protobuf:"bytes,3,opt,name=message_id,json=messageId,proto3" json:"message_id,omitempty"`
	Payload   []byte `protobuf:"bytes,4,opt,name=payload,proto3" json:"payload,omitempty"`
}

func (x *Envelope) Reset()         { *x = Envelope{} }
func (x *Envelope) String() string { return fmt.Sprintf("envelope{%s %s}", x.SensorId, x.MessageId) }
func (*Envelope) ProtoMessage()    {}

type Ack struct {
	MessageId string `protobuf:"bytes,1,opt,name=message_id,json=messageId,proto3" json:"message_id,omitempty"`
	Accepted  bool   `protobuf:"varint,2,opt,name=accepted,proto3" json:"accepted,omitempty"`
	Error     string `protobuf:"bytes,3,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *Ack) Reset()         { *x = Ack{} }
func (x *Ack) String() string { return fmt.Sprintf("ack{%s %t}", x.MessageId, x.Accepted) }
func (*Ack) ProtoMessage()    {}

type IngestClient interface {
	Stream(ctx context.Context, opts ...grpc.CallOption) (Ingest_StreamClient, error)
}
type ingestClient struct{ cc grpc.ClientConnInterface }

func NewIngestClient(cc grpc.ClientConnInterface) IngestClient { return &ingestClient{cc} }
func (c *ingestClient) Stream(ctx context.Context, opts ...grpc.CallOption) (Ingest_StreamClient, error) {
	s, e := c.cc.NewStream(ctx, &Ingest_ServiceDesc.Streams[0], "/fyke.v1.Ingest/Stream", opts...)
	if e != nil {
		return nil, e
	}
	return &ingestStreamClient{ClientStream: s}, nil
}

type Ingest_StreamClient interface {
	Send(*Envelope) error
	Recv() (*Ack, error)
	grpc.ClientStream
}
type ingestStreamClient struct{ grpc.ClientStream }

func (x *ingestStreamClient) Send(m *Envelope) error { return x.ClientStream.SendMsg(m) }
func (x *ingestStreamClient) Recv() (*Ack, error) {
	m := new(Ack)
	if e := x.ClientStream.RecvMsg(m); e != nil {
		return nil, e
	}
	return m, nil
}

type IngestServer interface {
	Stream(Ingest_StreamServer) error
}
type UnimplementedIngestServer struct{}

func (UnimplementedIngestServer) Stream(Ingest_StreamServer) error {
	return fmt.Errorf("unimplemented")
}

type Ingest_StreamServer interface {
	Send(*Ack) error
	Recv() (*Envelope, error)
	grpc.ServerStream
}
type ingestStreamServer struct{ grpc.ServerStream }

func (x *ingestStreamServer) Send(m *Ack) error { return x.ServerStream.SendMsg(m) }
func (x *ingestStreamServer) Recv() (*Envelope, error) {
	m := new(Envelope)
	if e := x.ServerStream.RecvMsg(m); e != nil {
		return nil, e
	}
	return m, nil
}
func RegisterIngestServer(s grpc.ServiceRegistrar, srv IngestServer) {
	s.RegisterService(&Ingest_ServiceDesc, srv)
}
func streamHandler(srv any, stream grpc.ServerStream) error {
	return srv.(IngestServer).Stream(&ingestStreamServer{ServerStream: stream})
}

var Ingest_ServiceDesc = grpc.ServiceDesc{ServiceName: "fyke.v1.Ingest", HandlerType: (*IngestServer)(nil), Streams: []grpc.StreamDesc{{StreamName: "Stream", Handler: streamHandler, ServerStreams: true, ClientStreams: true}}, Metadata: "api/fyke/v1/ingest.proto"}
