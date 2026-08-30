package transport

import "testing"

type heartbeatStream struct {
	Ingest_StreamClient
	sent *Envelope
}

func (s *heartbeatStream) Send(envelope *Envelope) error {
	s.sent = envelope
	return nil
}

func (s *heartbeatStream) Recv() (*Ack, error) {
	return &Ack{MessageId: s.sent.MessageId, Accepted: true}, nil
}

func TestClientHeartbeatIsVersionedAndAuthenticatedToSensor(t *testing.T) {
	client := &Client{sensorID: "ssh"}
	stream := &heartbeatStream{}
	if e := client.heartbeat(stream); e != nil {
		t.Fatal(e)
	}
	if stream.sent == nil || !stream.sent.Heartbeat || stream.sent.Version != Version || stream.sent.SensorId != "ssh" || stream.sent.MessageId == "" || len(stream.sent.Payload) != 0 {
		t.Fatalf("heartbeat envelope = %#v", stream.sent)
	}
}
