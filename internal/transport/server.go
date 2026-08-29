package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/ksahoo/fyke/internal/model"
	"github.com/ksahoo/fyke/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type Server struct {
	UnimplementedIngestServer
	store   *store.Store
	publish func(model.Event)
}

func NewServer(st *store.Store, publish func(model.Event)) *Server {
	return &Server{store: st, publish: publish}
}
func (s *Server) Stream(stream Ingest_StreamServer) error {
	sensorID, e := authenticatedSensor(stream.Context())
	if e != nil {
		return e
	}
	for {
		env, e := stream.Recv()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		ack := &Ack{MessageId: env.MessageId}
		if env.Version != Version {
			ack.Error = "unsupported transport version"
		} else if env.SensorId != sensorID {
			ack.Error = "certificate SAN does not match envelope sensor"
		} else {
			var event model.Event
			if e = json.Unmarshal(env.Payload, &event); e != nil {
				ack.Error = "invalid event payload"
			} else if event.SensorID != sensorID {
				ack.Error = "event sensor does not match certificate"
			} else if e = s.store.Insert(stream.Context(), event); e != nil {
				ack.Error = e.Error()
			} else {
				ack.Accepted = true
				if s.publish != nil {
					event.Evidence = nil
					s.publish(event)
				}
			}
		}
		if e = stream.Send(ack); e != nil {
			return e
		}
	}
}
func authenticatedSensor(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("missing peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return "", fmt.Errorf("mTLS client certificate required")
	}
	cert := ti.State.PeerCertificates[0]
	for _, name := range cert.DNSNames {
		if strings.HasPrefix(name, "sensor.") && len(name) > 7 {
			return strings.TrimPrefix(name, "sensor."), nil
		}
	}
	return "", fmt.Errorf("client certificate requires sensor.<id> DNS SAN")
}
func ServeGRPC(ctx context.Context, address string, tlsFiles [3]string, handler *Server) error {
	cert, e := tls.LoadX509KeyPair(tlsFiles[0], tlsFiles[1])
	if e != nil {
		return e
	}
	ca, e := os.ReadFile(tlsFiles[2])
	if e != nil {
		return e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return fmt.Errorf("invalid CA")
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13}
	ln, e := net.Listen("tcp", address)
	if e != nil {
		return e
	}
	g := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)), grpc.MaxRecvMsgSize(64<<20), grpc.MaxConcurrentStreams(1024))
	RegisterIngestServer(g, handler)
	go func() { <-ctx.Done(); g.GracefulStop() }()
	return g.Serve(ln)
}
