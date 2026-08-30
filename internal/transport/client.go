package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ksahoo/fyke/internal/model"
	"github.com/ksahoo/fyke/internal/spool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Client struct {
	sensorID, address string
	spool             *spool.Spool
	tls               *tls.Config
}

func NewClient(sensorID, address string, sp *spool.Spool, certFile, keyFile, caFile string) (*Client, error) {
	cert, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		return nil, e
	}
	ca, e := os.ReadFile(caFile)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid CA")
	}
	host := address
	if i := strings.LastIndex(address, ":"); i >= 0 {
		host = address[:i]
	}
	return &Client{sensorID: sensorID, address: address, spool: sp, tls: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13, ServerName: host}}, nil
}
func (c *Client) Emit(ctx context.Context, e model.Event) error {
	b, er := json.Marshal(e)
	if er != nil {
		return er
	}
	return c.spool.Put(e.ID, b)
}
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if e := c.runOnce(ctx); e != nil {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}
func (c *Client) runOnce(ctx context.Context) error {
	conn, e := grpc.NewClient(c.address, grpc.WithTransportCredentials(credentials.NewTLS(c.tls)))
	if e != nil {
		return e
	}
	defer conn.Close()
	stream, e := NewIngestClient(conn).Stream(ctx)
	if e != nil {
		return e
	}
	for {
		records, e := c.spool.List()
		if e != nil {
			return e
		}
		if len(records) == 0 {
			if e = c.heartbeat(stream); e != nil {
				return e
			}
			select {
			case <-c.spool.Wake():
				continue
			case <-time.After(30 * time.Second):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		for _, r := range records {
			if e = stream.Send(&Envelope{Version: Version, SensorId: c.sensorID, MessageId: r.ID, Payload: r.Data}); e != nil {
				return e
			}
			ack, e := stream.Recv()
			if e != nil {
				return e
			}
			if ack.MessageId != r.ID {
				return fmt.Errorf("ack mismatch")
			}
			if !ack.Accepted {
				return fmt.Errorf("controller rejected event: %s", ack.Error)
			}
			if e = c.spool.Ack(r.ID); e != nil {
				return e
			}
		}
	}
}

func (c *Client) heartbeat(stream Ingest_StreamClient) error {
	id := model.NewUUIDv7(time.Now())
	if e := stream.Send(&Envelope{Version: Version, SensorId: c.sensorID, MessageId: id, Heartbeat: true}); e != nil {
		return e
	}
	ack, e := stream.Recv()
	if e != nil {
		return e
	}
	if ack.MessageId != id {
		return fmt.Errorf("heartbeat ack mismatch")
	}
	if !ack.Accepted {
		return fmt.Errorf("controller rejected heartbeat: %s", ack.Error)
	}
	return nil
}
