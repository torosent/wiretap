package model

import (
	"net"
	"testing"
	"time"
)

func TestConnectionState_String(t *testing.T) {
	cases := map[ConnectionState]string{
		ConnectionStateNew:     "NEW",
		ConnectionStateOpen:    "OPEN",
		ConnectionStateClosing: "CLOSING",
		ConnectionStateClosed:  "CLOSED",
		ConnectionStateReset:   "RESET",
		ConnectionState(99):    "UNKNOWN",
	}

	for state, want := range cases {
		if got := state.String(); got != want {
			t.Errorf("State %d = %s, want %s", state, got, want)
		}
	}
}

func TestConnection_AddPacketAndState(t *testing.T) {
	pkt := &Packet{
		Index:      1,
		Timestamp:  time.Now(),
		SrcIP:      net.ParseIP("10.0.0.1"),
		DstIP:      net.ParseIP("10.0.0.2"),
		SrcPort:    1234,
		DstPort:    80,
		Protocol:   ProtocolTCP,
		CapturedLen: 10,
		TCPFlags:   TCPFlags{SYN: true},
	}

	conn := NewConnection(1, pkt)
	if conn.State != ConnectionStateNew {
		t.Errorf("Initial state = %s", conn.State)
	}

	resp := &Packet{
		Index:      2,
		Timestamp:  pkt.Timestamp.Add(time.Second),
		SrcIP:      pkt.DstIP,
		DstIP:      pkt.SrcIP,
		SrcPort:    pkt.DstPort,
		DstPort:    pkt.SrcPort,
		Protocol:   ProtocolTCP,
		CapturedLen: 20,
		TCPFlags:   TCPFlags{SYN: true, ACK: true},
	}
	conn.AddPacket(resp)
	if conn.State != ConnectionStateOpen {
		t.Errorf("State after SYN-ACK = %s", conn.State)
	}
	if conn.BytesReceived == 0 {
		t.Error("Expected BytesReceived to increase")
	}

	fin := &Packet{
		Index:      3,
		Timestamp:  pkt.Timestamp.Add(2 * time.Second),
		SrcIP:      pkt.SrcIP,
		DstIP:      pkt.DstIP,
		SrcPort:    pkt.SrcPort,
		DstPort:    pkt.DstPort,
		Protocol:   ProtocolTCP,
		CapturedLen: 5,
		TCPFlags:   TCPFlags{FIN: true},
	}
	conn.AddPacket(fin)
	if conn.State != ConnectionStateClosing {
		t.Errorf("State after FIN = %s", conn.State)
	}
}

func TestConnection_DurationAndTotalBytes(t *testing.T) {
	start := time.Now()
	pkt := &Packet{
		Index:      1,
		Timestamp:  start,
		SrcIP:      net.ParseIP("10.0.0.1"),
		DstIP:      net.ParseIP("10.0.0.2"),
		SrcPort:    1111,
		DstPort:    2222,
		Protocol:   ProtocolTCP,
		CapturedLen: 10,
	}
	conn := NewConnection(1, pkt)
	conn.EndTime = start.Add(5 * time.Second)
	if conn.Duration() != 5*time.Second {
		t.Errorf("Duration = %v", conn.Duration())
	}

	conn.BytesSent = 10
	conn.BytesReceived = 20
	if conn.TotalBytes() != 30 {
		t.Errorf("TotalBytes = %d", conn.TotalBytes())
	}
}

func TestStream_Append_Reset(t *testing.T) {
	stream := &Stream{Direction: DirectionClientToServer}
	stream.Append([]byte("hello"), 100)
	if stream.BytesSeen == 0 || stream.NextSeq == 0 {
		t.Error("Stream append did not update tracking")
	}
	if len(stream.Data) == 0 {
		t.Error("Expected stream data to be appended")
	}

	stream.Reset()
	if stream.BytesSeen != 0 || len(stream.Data) != 0 {
		t.Error("Stream reset failed")
	}
}

func TestConnectionTracker(t *testing.T) {
	tracker := NewConnectionTracker()
	pkt := &Packet{
		Index:      1,
		Timestamp:  time.Now(),
		SrcIP:      net.ParseIP("10.0.0.1"),
		DstIP:      net.ParseIP("10.0.0.2"),
		SrcPort:    1234,
		DstPort:    80,
		Protocol:   ProtocolTCP,
		CapturedLen: 10,
	}

	conn1 := tracker.GetOrCreate(pkt)
	conn2 := tracker.GetOrCreate(pkt)
	if conn1.ID != conn2.ID {
		t.Error("Expected same connection for same flow")
	}
	if tracker.Count() != 1 {
		t.Errorf("Count = %d, want 1", tracker.Count())
	}

	if tracker.Get(conn1.ID) == nil {
		t.Error("Expected to retrieve connection by ID")
	}
	if tracker.GetByFlow(pkt.FlowHash()) == nil {
		t.Error("Expected to retrieve connection by flow hash")
	}

	if len(tracker.All()) != 1 {
		t.Error("Expected one connection in All()")
	}

	tracker.Clear()
	if tracker.Count() != 0 {
		t.Error("Expected tracker to be cleared")
	}
}
