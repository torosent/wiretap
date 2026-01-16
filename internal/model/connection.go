// Package model defines connection and stream models.
package model

import (
	"sync"
	"time"
)

// ConnectionState represents the state of a TCP connection.
type ConnectionState uint8

// Connection states.
const (
	ConnectionStateNew ConnectionState = iota
	ConnectionStateOpen
	ConnectionStateClosing
	ConnectionStateClosed
	ConnectionStateReset
)

// String returns the connection state name.
func (s ConnectionState) String() string {
	switch s {
	case ConnectionStateNew:
		return "NEW"
	case ConnectionStateOpen:
		return "OPEN"
	case ConnectionStateClosing:
		return "CLOSING"
	case ConnectionStateClosed:
		return "CLOSED"
	case ConnectionStateReset:
		return "RESET"
	default:
		return "UNKNOWN"
	}
}

// Connection represents a tracked TCP connection or UDP flow.
type Connection struct {
	mu sync.RWMutex

	// ID is a unique connection identifier
	ID uint64

	// FiveTuple identifies this connection
	FiveTuple FiveTuple

	// State of the connection
	State ConnectionState

	// Timestamps
	StartTime time.Time
	EndTime   time.Time
	LastSeen  time.Time

	// Packet indices
	FirstPacket uint64
	LastPacket  uint64
	PacketCount uint64

	// Byte counts
	BytesSent     uint64
	BytesReceived uint64

	// Application protocol detected
	AppProtocol Protocol

	// Streams for this connection (client->server, server->client)
	ClientStream *Stream
	ServerStream *Stream

	// HTTP conversations on this connection
	HTTPConversations []*HTTPConversation

	// TLS info if this is an encrypted connection
	TLSInfo *TLSInfo
}

// NewConnection creates a new connection from a packet.
func NewConnection(id uint64, pkt *Packet) *Connection {
	return &Connection{
		ID:           id,
		FiveTuple:    pkt.FiveTuple(),
		State:        ConnectionStateNew,
		StartTime:    pkt.Timestamp,
		LastSeen:     pkt.Timestamp,
		FirstPacket:  pkt.Index,
		LastPacket:   pkt.Index,
		PacketCount:  1,
		ClientStream: &Stream{Direction: DirectionClientToServer},
		ServerStream: &Stream{Direction: DirectionServerToClient},
	}
}

// AddPacket updates the connection with a new packet.
func (c *Connection) AddPacket(pkt *Packet) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.LastSeen = pkt.Timestamp
	c.LastPacket = pkt.Index
	c.PacketCount++

	// Update state based on TCP flags
	if pkt.Protocol == ProtocolTCP {
		c.updateTCPState(pkt.TCPFlags)
	}

	// Determine direction and update byte counts
	if c.isClientToServer(pkt) {
		c.BytesSent += uint64(pkt.CapturedLen)
	} else {
		c.BytesReceived += uint64(pkt.CapturedLen)
	}
}

// updateTCPState updates connection state based on TCP flags.
func (c *Connection) updateTCPState(flags TCPFlags) {
	switch {
	case flags.RST:
		c.State = ConnectionStateReset
	case flags.FIN:
		if c.State == ConnectionStateClosing {
			c.State = ConnectionStateClosed
		} else {
			c.State = ConnectionStateClosing
		}
	case flags.SYN && flags.ACK:
		c.State = ConnectionStateOpen
	case flags.SYN:
		c.State = ConnectionStateNew
	}
}

// isClientToServer checks if a packet is from client to server.
func (c *Connection) isClientToServer(pkt *Packet) bool {
	return pkt.SrcIP.Equal(c.FiveTuple.SrcIP) && pkt.SrcPort == c.FiveTuple.SrcPort
}

// Duration returns the connection duration.
func (c *Connection) Duration() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.EndTime.IsZero() {
		return c.LastSeen.Sub(c.StartTime)
	}
	return c.EndTime.Sub(c.StartTime)
}

// TotalBytes returns the total bytes transferred.
func (c *Connection) TotalBytes() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.BytesSent + c.BytesReceived
}

// StreamDirection represents the direction of a stream.
type StreamDirection uint8

// Stream directions.
const (
	DirectionClientToServer StreamDirection = iota
	DirectionServerToClient
)

// String returns the direction name.
func (d StreamDirection) String() string {
	switch d {
	case DirectionClientToServer:
		return "client→server"
	case DirectionServerToClient:
		return "server→client"
	default:
		return "unknown"
	}
}

// Stream represents a unidirectional TCP stream.
type Stream struct {
	mu sync.Mutex

	// ID is a unique stream identifier
	ID uint32

	// Direction of this stream
	Direction StreamDirection

	// Reassembled data
	Data []byte

	// Sequence tracking
	NextSeq     uint32
	BytesSeen   uint64
	GapCount    int
	OverlapSize int

	// Packets in this stream
	PacketIndices []uint64
}

// Append adds data to the stream.
func (s *Stream) Append(data []byte, seq uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Simple append for now - proper reassembly would handle gaps
	s.Data = append(s.Data, data...)
	s.BytesSeen += uint64(len(data))
	s.NextSeq = seq + uint32(len(data))
}

// Reset clears the stream data.
func (s *Stream) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Data = nil
	s.BytesSeen = 0
	s.GapCount = 0
	s.OverlapSize = 0
}

// ConnectionTracker manages active connections.
type ConnectionTracker struct {
	mu          sync.RWMutex
	connections map[uint64]*Connection
	byHash      map[uint64]*Connection
	nextID      uint64
}

// NewConnectionTracker creates a new connection tracker.
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[uint64]*Connection),
		byHash:      make(map[uint64]*Connection),
		nextID:      1,
	}
}

// GetOrCreate gets an existing connection or creates a new one.
func (ct *ConnectionTracker) GetOrCreate(pkt *Packet) *Connection {
	hash := pkt.FlowHash()

	ct.mu.Lock()
	defer ct.mu.Unlock()

	if conn, ok := ct.byHash[hash]; ok {
		return conn
	}

	conn := NewConnection(ct.nextID, pkt)
	ct.nextID++

	ct.connections[conn.ID] = conn
	ct.byHash[hash] = conn

	return conn
}

// Get retrieves a connection by ID.
func (ct *ConnectionTracker) Get(id uint64) *Connection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.connections[id]
}

// GetByFlow retrieves a connection by flow hash.
func (ct *ConnectionTracker) GetByFlow(hash uint64) *Connection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.byHash[hash]
}

// All returns all connections.
func (ct *ConnectionTracker) All() []*Connection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	result := make([]*Connection, 0, len(ct.connections))
	for _, conn := range ct.connections {
		result = append(result, conn)
	}
	return result
}

// Count returns the number of tracked connections.
func (ct *ConnectionTracker) Count() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.connections)
}

// Clear removes all connections.
func (ct *ConnectionTracker) Clear() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.connections = make(map[uint64]*Connection)
	ct.byHash = make(map[uint64]*Connection)
}
