package capture

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/wiretap/wiretap/internal/model"
)

func TestStreamFactoryAndAssembler(t *testing.T) {
	called := make(chan struct{}, 1)
	factory := NewStreamFactory(func(stream *TCPStream) {
		called <- struct{}{}
	})

	netFlow := gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2})
	transFlow := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0, 80}, []byte{0, 1})

	_ = factory.New(netFlow, transFlow)

	select {
	case <-called:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Expected handler to be called")
	}

	stream := factory.GetStream(netFlow, transFlow)
	if stream == nil {
		t.Fatal("Expected stream to be stored")
	}

	if len(factory.AllStreams()) != 1 {
		t.Errorf("Expected 1 stream, got %d", len(factory.AllStreams()))
	}

	stream.Close()
	if !stream.IsClosed() {
		t.Error("Expected stream to be closed")
	}

	assembler := NewAssembler(nil)
	tcp := &layers.TCP{Seq: 1}
	assembler.AssembleWithTimestamp(netFlow, transFlow, tcp, gopacket.CaptureInfo{Timestamp: time.Now()})
	assembler.FlushOlderThan(gopacket.CaptureInfo{Timestamp: time.Now()})
	assembler.FlushAll()
}

func TestConnectionReassembler(t *testing.T) {
	tracker := model.NewConnectionTracker()
	reassembler := NewConnectionReassembler(tracker)

	pkt := &model.Packet{
		Index:      1,
		Timestamp:  time.Now(),
		SrcIP:      []byte{10, 0, 0, 1},
		DstIP:      []byte{10, 0, 0, 2},
		SrcPort:    1234,
		DstPort:    80,
		Protocol:   model.ProtocolTCP,
		CapturedLen: 4,
	}

	reassembler.AddData(pkt, []byte("ping"), true)
	reassembler.AddData(pkt, []byte("pong"), false)

	conn := reassembler.GetConnection(pkt.FlowHash())
	if conn == nil {
		t.Fatal("Expected reassembled connection")
	}
	if len(conn.ClientData) == 0 || len(conn.ServerData) == 0 {
		t.Error("Expected client/server data")
	}

	all := reassembler.All()
	if len(all) != 1 {
		t.Errorf("Expected 1 connection, got %d", len(all))
	}
}

func TestStreamKey(t *testing.T) {
	netFlow := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 168, 1, 1}, []byte{192, 168, 1, 2})
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 8080)
	transFlow := gopacket.NewFlow(layers.EndpointTCPPort, portBytes, []byte{0, 1})

	key := streamKey(netFlow, transFlow)
	if key == "" {
		t.Error("Expected stream key")
	}
}
