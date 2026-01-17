// Package capture provides TCP stream reassembly.
package capture

import (
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/gopacket/gopacket/tcpassembly/tcpreader"
	"github.com/wiretap/wiretap/internal/model"
)

// StreamHandler is called when a new stream is created.
type StreamHandler func(stream *TCPStream)

// StreamFactory creates TCP streams for the assembler.
type StreamFactory struct {
	mu      sync.Mutex
	handler StreamHandler
	streams map[string]*TCPStream
}

// NewStreamFactory creates a new stream factory.
func NewStreamFactory(handler StreamHandler) *StreamFactory {
	return &StreamFactory{
		handler: handler,
		streams: make(map[string]*TCPStream),
	}
}

// New creates a new stream for the assembler.
func (f *StreamFactory) New(netFlow, transFlow gopacket.Flow) tcpassembly.Stream {
	stream := &TCPStream{
		netFlow:   netFlow,
		transFlow: transFlow,
		reader:    tcpreader.NewReaderStream(),
	}

	// Store stream
	key := streamKey(netFlow, transFlow)
	f.mu.Lock()
	f.streams[key] = stream
	f.mu.Unlock()

	// Notify handler
	if f.handler != nil {
		go f.handler(stream)
	}

	return &stream.reader
}

// GetStream retrieves a stream by its flows.
func (f *StreamFactory) GetStream(netFlow, transFlow gopacket.Flow) *TCPStream {
	key := streamKey(netFlow, transFlow)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.streams[key]
}

// AllStreams returns all tracked streams.
func (f *StreamFactory) AllStreams() []*TCPStream {
	f.mu.Lock()
	defer f.mu.Unlock()

	streams := make([]*TCPStream, 0, len(f.streams))
	for _, s := range f.streams {
		streams = append(streams, s)
	}
	return streams
}

// streamKey creates a unique key for a stream.
func streamKey(netFlow, transFlow gopacket.Flow) string {
	return netFlow.String() + ":" + transFlow.String()
}

// TCPStream represents a reassembled TCP stream.
type TCPStream struct {
	netFlow   gopacket.Flow
	transFlow gopacket.Flow
	reader    tcpreader.ReaderStream

	// Metadata
	mu        sync.Mutex
	data      []byte
	byteCount int64
	closed    bool
}

// Read reads from the stream.
func (s *TCPStream) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	if n > 0 {
		s.mu.Lock()
		s.byteCount += int64(n)
		s.data = append(s.data, p[:n]...)
		s.mu.Unlock()
	}
	return n, err
}

// Data returns all data read from the stream so far.
func (s *TCPStream) Data() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// ByteCount returns the number of bytes read.
func (s *TCPStream) ByteCount() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byteCount
}

// NetFlow returns the network flow (IPs).
func (s *TCPStream) NetFlow() gopacket.Flow {
	return s.netFlow
}

// TransFlow returns the transport flow (ports).
func (s *TCPStream) TransFlow() gopacket.Flow {
	return s.transFlow
}

// Close marks the stream as closed.
func (s *TCPStream) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}

// IsClosed returns true if the stream is closed.
func (s *TCPStream) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Assembler wraps tcpassembly.Assembler with additional functionality.
type Assembler struct {
	factory   *StreamFactory
	assembler *tcpassembly.Assembler
	pool      *tcpassembly.StreamPool
}

// NewAssembler creates a new TCP assembler.
func NewAssembler(handler StreamHandler) *Assembler {
	factory := NewStreamFactory(handler)
	pool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(pool)

	return &Assembler{
		factory:   factory,
		assembler: assembler,
		pool:      pool,
	}
}

// AssembleWithTimestamp adds a packet to the assembler.
func (a *Assembler) AssembleWithTimestamp(netFlow, transFlow gopacket.Flow, tcp *layers.TCP, timestamp gopacket.CaptureInfo) {
	a.assembler.AssembleWithTimestamp(netFlow, tcp, timestamp.Timestamp)
}

// FlushOlderThan flushes streams older than the given time.
func (a *Assembler) FlushOlderThan(t gopacket.CaptureInfo) {
	a.assembler.FlushOlderThan(t.Timestamp)
}

// FlushAll flushes all streams.
func (a *Assembler) FlushAll() {
	a.assembler.FlushAll()
}

// GetStream retrieves a stream by its flows.
func (a *Assembler) GetStream(netFlow, transFlow gopacket.Flow) *TCPStream {
	return a.factory.GetStream(netFlow, transFlow)
}

// AllStreams returns all tracked streams.
func (a *Assembler) AllStreams() []*TCPStream {
	return a.factory.AllStreams()
}

// ConnectionReassembler reassembles TCP streams by connection.
type ConnectionReassembler struct {
	mu          sync.RWMutex
	connections map[uint64]*ReassembledConnection
	tracker     *model.ConnectionTracker
}

// ReassembledConnection holds reassembled data for a connection.
type ReassembledConnection struct {
	Connection *model.Connection
	ClientData []byte
	ServerData []byte
	mu         sync.Mutex
}

// NewConnectionReassembler creates a new connection reassembler.
func NewConnectionReassembler(tracker *model.ConnectionTracker) *ConnectionReassembler {
	return &ConnectionReassembler{
		connections: make(map[uint64]*ReassembledConnection),
		tracker:     tracker,
	}
}

// AddData adds reassembled data to a connection.
func (r *ConnectionReassembler) AddData(pkt *model.Packet, payload []byte, isClientToServer bool) {
	hash := pkt.FlowHash()

	r.mu.Lock()
	rc, ok := r.connections[hash]
	if !ok {
		conn := r.tracker.GetByFlow(hash)
		if conn == nil {
			conn = r.tracker.GetOrCreate(pkt)
		}
		rc = &ReassembledConnection{
			Connection: conn,
		}
		r.connections[hash] = rc
	}
	r.mu.Unlock()

	rc.mu.Lock()
	if isClientToServer {
		rc.ClientData = append(rc.ClientData, payload...)
	} else {
		rc.ServerData = append(rc.ServerData, payload...)
	}
	rc.mu.Unlock()
}

// GetConnection retrieves reassembled data for a connection.
func (r *ConnectionReassembler) GetConnection(hash uint64) *ReassembledConnection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.connections[hash]
}

// All returns all reassembled connections.
func (r *ConnectionReassembler) All() []*ReassembledConnection {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*ReassembledConnection, 0, len(r.connections))
	for _, rc := range r.connections {
		result = append(result, rc)
	}
	return result
}
