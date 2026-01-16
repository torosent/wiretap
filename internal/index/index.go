// Package index provides memory-mapped packet indexing for fast random access.
package index

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/edsrzf/mmap-go"
	"github.com/wiretap/wiretap/internal/model"
)

// Index format constants
const (
	MagicNumber    uint32 = 0x57545049 // "WTPI" - WireTap Index
	CurrentVersion uint32 = 1
	HeaderSize     int    = 64
	PacketEntrySize int   = 48
	ConnectionEntrySize int = 72
)

// Common errors
var (
	ErrInvalidMagic   = errors.New("invalid index magic number")
	ErrVersionMismatch = errors.New("index version mismatch")
	ErrCorruptedIndex = errors.New("corrupted index file")
	ErrIndexNotOpen   = errors.New("index not open")
	ErrOutOfBounds    = errors.New("index out of bounds")
)

// IndexHeader represents the header of an index file.
type IndexHeader struct {
	Magic            uint32
	Version          uint32
	PacketCount      uint64
	ConnectionCount  uint64
	CreatedAt        int64
	PcapFileSize     int64
	PcapFileMD5      [16]byte
	Reserved         [8]byte
}

// PacketIndexEntry represents a single packet's index entry.
// Size: 48 bytes
type PacketIndexEntry struct {
	Offset      int64    // Offset in pcap file
	Length      uint32   // Packet length
	Timestamp   int64    // Unix nanoseconds
	Protocol    uint16   // Protocol identifier
	Flags       uint16   // TCP flags or other metadata
	ConnID      uint32   // Connection ID (index into connection table)
	SrcPort     uint16   // Source port
	DstPort     uint16   // Destination port
	Reserved    [8]byte  // Reserved for future use
}

// ConnectionIndexEntry represents a connection's index entry.
// Size: 64 bytes
type ConnectionIndexEntry struct {
	SrcIP         [16]byte // IPv4 or IPv6 address
	DstIP         [16]byte // IPv4 or IPv6 address
	SrcPort       uint16
	DstPort       uint16
	Protocol      uint16
	IsIPv6        uint8
	State         uint8
	FirstPacket   uint64   // Index of first packet
	LastPacket    uint64   // Index of last packet
	PacketCount   uint32
	ByteCount     uint64
	Reserved      [4]byte
}

// Index provides read access to a memory-mapped packet index.
type Index struct {
	mu          sync.RWMutex
	file        *os.File
	data        mmap.MMap
	header      *IndexHeader
	packetBase  int
	connBase    int
	pcapPath    string
}

// Open opens an existing index file.
func Open(indexPath string) (*Index, error) {
	f, err := os.Open(indexPath)
	if err != nil {
		return nil, fmt.Errorf("open index: %w", err)
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat index: %w", err)
	}

	if fi.Size() < int64(HeaderSize) {
		f.Close()
		return nil, ErrCorruptedIndex
	}

	data, err := mmap.Map(f, mmap.RDONLY, 0)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("mmap index: %w", err)
	}

	idx := &Index{
		file: f,
		data: data,
	}

	if err := idx.readHeader(); err != nil {
		idx.Close()
		return nil, err
	}

	return idx, nil
}

// readHeader parses the index header from mapped data.
func (idx *Index) readHeader() error {
	idx.header = &IndexHeader{
		Magic:           binary.LittleEndian.Uint32(idx.data[0:4]),
		Version:         binary.LittleEndian.Uint32(idx.data[4:8]),
		PacketCount:     binary.LittleEndian.Uint64(idx.data[8:16]),
		ConnectionCount: binary.LittleEndian.Uint64(idx.data[16:24]),
		CreatedAt:       int64(binary.LittleEndian.Uint64(idx.data[24:32])),
		PcapFileSize:    int64(binary.LittleEndian.Uint64(idx.data[32:40])),
	}
	copy(idx.header.PcapFileMD5[:], idx.data[40:56])

	if idx.header.Magic != MagicNumber {
		return ErrInvalidMagic
	}

	if idx.header.Version != CurrentVersion {
		return ErrVersionMismatch
	}

	// Calculate offsets
	idx.packetBase = HeaderSize
	idx.connBase = HeaderSize + int(idx.header.PacketCount)*PacketEntrySize

	return nil
}

// Close closes the index file and releases the memory map.
func (idx *Index) Close() error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	var errs []error

	if idx.data != nil {
		if err := idx.data.Unmap(); err != nil {
			errs = append(errs, err)
		}
		idx.data = nil
	}

	if idx.file != nil {
		if err := idx.file.Close(); err != nil {
			errs = append(errs, err)
		}
		idx.file = nil
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// PacketCount returns the total number of indexed packets.
func (idx *Index) PacketCount() uint64 {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	
	if idx.header == nil {
		return 0
	}
	return idx.header.PacketCount
}

// ConnectionCount returns the total number of indexed connections.
func (idx *Index) ConnectionCount() uint64 {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	
	if idx.header == nil {
		return 0
	}
	return idx.header.ConnectionCount
}

// GetPacket retrieves a packet index entry by packet number.
func (idx *Index) GetPacket(packetNum uint64) (*PacketIndexEntry, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if idx.data == nil {
		return nil, ErrIndexNotOpen
	}

	if packetNum >= idx.header.PacketCount {
		return nil, ErrOutOfBounds
	}

	offset := idx.packetBase + int(packetNum)*PacketEntrySize
	return idx.readPacketEntry(offset), nil
}

// GetPacketRange retrieves a range of packet index entries.
func (idx *Index) GetPacketRange(start, end uint64) ([]*PacketIndexEntry, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if idx.data == nil {
		return nil, ErrIndexNotOpen
	}

	if start >= idx.header.PacketCount || end > idx.header.PacketCount || start > end {
		return nil, ErrOutOfBounds
	}

	entries := make([]*PacketIndexEntry, 0, end-start)
	for i := start; i < end; i++ {
		offset := idx.packetBase + int(i)*PacketEntrySize
		entries = append(entries, idx.readPacketEntry(offset))
	}

	return entries, nil
}

// readPacketEntry reads a single packet entry at the given offset.
func (idx *Index) readPacketEntry(offset int) *PacketIndexEntry {
	return &PacketIndexEntry{
		Offset:    int64(binary.LittleEndian.Uint64(idx.data[offset : offset+8])),
		Length:    binary.LittleEndian.Uint32(idx.data[offset+8 : offset+12]),
		Timestamp: int64(binary.LittleEndian.Uint64(idx.data[offset+12 : offset+20])),
		Protocol:  binary.LittleEndian.Uint16(idx.data[offset+20 : offset+22]),
		Flags:     binary.LittleEndian.Uint16(idx.data[offset+22 : offset+24]),
		ConnID:    binary.LittleEndian.Uint32(idx.data[offset+24 : offset+28]),
		SrcPort:   binary.LittleEndian.Uint16(idx.data[offset+28 : offset+30]),
		DstPort:   binary.LittleEndian.Uint16(idx.data[offset+30 : offset+32]),
	}
}

// GetConnection retrieves a connection index entry by connection number.
func (idx *Index) GetConnection(connNum uint64) (*ConnectionIndexEntry, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if idx.data == nil {
		return nil, ErrIndexNotOpen
	}

	if connNum >= idx.header.ConnectionCount {
		return nil, ErrOutOfBounds
	}

	offset := idx.connBase + int(connNum)*ConnectionEntrySize
	return idx.readConnectionEntry(offset), nil
}

// readConnectionEntry reads a single connection entry at the given offset.
func (idx *Index) readConnectionEntry(offset int) *ConnectionIndexEntry {
	entry := &ConnectionIndexEntry{
		SrcPort:     binary.LittleEndian.Uint16(idx.data[offset+32 : offset+34]),
		DstPort:     binary.LittleEndian.Uint16(idx.data[offset+34 : offset+36]),
		Protocol:    binary.LittleEndian.Uint16(idx.data[offset+36 : offset+38]),
		IsIPv6:      idx.data[offset+38],
		State:       idx.data[offset+39],
		FirstPacket: binary.LittleEndian.Uint64(idx.data[offset+40 : offset+48]),
		LastPacket:  binary.LittleEndian.Uint64(idx.data[offset+48 : offset+56]),
		PacketCount: binary.LittleEndian.Uint32(idx.data[offset+56 : offset+60]),
		ByteCount:   binary.LittleEndian.Uint64(idx.data[offset+60 : offset+68]),
	}
	copy(entry.SrcIP[:], idx.data[offset:offset+16])
	copy(entry.DstIP[:], idx.data[offset+16:offset+32])
	return entry
}

// SearchByTime finds packets within the given time range.
func (idx *Index) SearchByTime(start, end time.Time) ([]*PacketIndexEntry, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if idx.data == nil {
		return nil, ErrIndexNotOpen
	}

	startNano := start.UnixNano()
	endNano := end.UnixNano()

	// Binary search for start position
	startIdx := idx.binarySearchTime(startNano, true)
	if startIdx >= int(idx.header.PacketCount) {
		return nil, nil // No packets in range
	}

	// Collect packets until we exceed end time
	var results []*PacketIndexEntry
	for i := uint64(startIdx); i < idx.header.PacketCount; i++ {
		entry, _ := idx.GetPacket(i)
		if entry.Timestamp > endNano {
			break
		}
		results = append(results, entry)
	}

	return results, nil
}

// binarySearchTime performs binary search to find packet index by timestamp.
func (idx *Index) binarySearchTime(targetNano int64, findFirst bool) int {
	low := 0
	high := int(idx.header.PacketCount)
	result := high

	for low < high {
		mid := (low + high) / 2
		offset := idx.packetBase + mid*PacketEntrySize
		ts := int64(binary.LittleEndian.Uint64(idx.data[offset+12 : offset+20]))

		if ts >= targetNano {
			result = mid
			high = mid
		} else {
			low = mid + 1
		}
	}

	return result
}

// SearchByIP finds packets matching the given IP address.
func (idx *Index) SearchByIP(ip net.IP) ([]*PacketIndexEntry, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if idx.data == nil {
		return nil, ErrIndexNotOpen
	}

	// First, find connections involving this IP
	var matchingConns []uint64
	for i := uint64(0); i < idx.header.ConnectionCount; i++ {
		conn, _ := idx.GetConnection(i)
		
		var srcIP, dstIP net.IP
		if conn.IsIPv6 == 1 {
			srcIP = net.IP(conn.SrcIP[:])
			dstIP = net.IP(conn.DstIP[:])
		} else {
			srcIP = net.IP(conn.SrcIP[12:16])
			dstIP = net.IP(conn.DstIP[12:16])
		}

		if srcIP.Equal(ip) || dstIP.Equal(ip) {
			matchingConns = append(matchingConns, i)
		}
	}

	// Now collect all packets from matching connections
	var results []*PacketIndexEntry
	for i := uint64(0); i < idx.header.PacketCount; i++ {
		entry, _ := idx.GetPacket(i)
		for _, connID := range matchingConns {
			if uint64(entry.ConnID) == connID {
				results = append(results, entry)
				break
			}
		}
	}

	return results, nil
}

// SearchByPort finds packets matching the given port number.
func (idx *Index) SearchByPort(port uint16) ([]*PacketIndexEntry, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if idx.data == nil {
		return nil, ErrIndexNotOpen
	}

	var results []*PacketIndexEntry
	for i := uint64(0); i < idx.header.PacketCount; i++ {
		entry, _ := idx.GetPacket(i)
		if entry.SrcPort == port || entry.DstPort == port {
			results = append(results, entry)
		}
	}

	return results, nil
}

// SearchByProtocol finds packets matching the given protocol.
func (idx *Index) SearchByProtocol(protocol model.Protocol) ([]*PacketIndexEntry, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if idx.data == nil {
		return nil, ErrIndexNotOpen
	}

	var results []*PacketIndexEntry
	for i := uint64(0); i < idx.header.PacketCount; i++ {
		entry, _ := idx.GetPacket(i)
		if entry.Protocol == uint16(protocol) {
			results = append(results, entry)
		}
	}

	return results, nil
}

// Header returns a copy of the index header.
func (idx *Index) Header() *IndexHeader {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	
	if idx.header == nil {
		return nil
	}
	
	h := *idx.header
	return &h
}

// Verify checks the integrity of the index against its pcap file.
func (idx *Index) Verify(pcapPath string) error {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if idx.data == nil {
		return ErrIndexNotOpen
	}

	fi, err := os.Stat(pcapPath)
	if err != nil {
		return fmt.Errorf("stat pcap: %w", err)
	}

	if fi.Size() != idx.header.PcapFileSize {
		return fmt.Errorf("pcap size mismatch: expected %d, got %d", idx.header.PcapFileSize, fi.Size())
	}

	return nil
}

// Write writes index data to an io.Writer.
func Write(w io.Writer, header *IndexHeader, packets []*PacketIndexEntry, conns []*ConnectionIndexEntry) error {
	// Write header
	headerBuf := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(headerBuf[0:4], header.Magic)
	binary.LittleEndian.PutUint32(headerBuf[4:8], header.Version)
	binary.LittleEndian.PutUint64(headerBuf[8:16], header.PacketCount)
	binary.LittleEndian.PutUint64(headerBuf[16:24], header.ConnectionCount)
	binary.LittleEndian.PutUint64(headerBuf[24:32], uint64(header.CreatedAt))
	binary.LittleEndian.PutUint64(headerBuf[32:40], uint64(header.PcapFileSize))
	copy(headerBuf[40:56], header.PcapFileMD5[:])

	if _, err := w.Write(headerBuf); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Write packet entries
	packetBuf := make([]byte, PacketEntrySize)
	for _, pkt := range packets {
		binary.LittleEndian.PutUint64(packetBuf[0:8], uint64(pkt.Offset))
		binary.LittleEndian.PutUint32(packetBuf[8:12], pkt.Length)
		binary.LittleEndian.PutUint64(packetBuf[12:20], uint64(pkt.Timestamp))
		binary.LittleEndian.PutUint16(packetBuf[20:22], pkt.Protocol)
		binary.LittleEndian.PutUint16(packetBuf[22:24], pkt.Flags)
		binary.LittleEndian.PutUint32(packetBuf[24:28], pkt.ConnID)
		binary.LittleEndian.PutUint16(packetBuf[28:30], pkt.SrcPort)
		binary.LittleEndian.PutUint16(packetBuf[30:32], pkt.DstPort)

		if _, err := w.Write(packetBuf); err != nil {
			return fmt.Errorf("write packet entry: %w", err)
		}
	}

	// Write connection entries
	connBuf := make([]byte, ConnectionEntrySize)
	for _, conn := range conns {
		copy(connBuf[0:16], conn.SrcIP[:])
		copy(connBuf[16:32], conn.DstIP[:])
		binary.LittleEndian.PutUint16(connBuf[32:34], conn.SrcPort)
		binary.LittleEndian.PutUint16(connBuf[34:36], conn.DstPort)
		binary.LittleEndian.PutUint16(connBuf[36:38], conn.Protocol)
		connBuf[38] = conn.IsIPv6
		connBuf[39] = conn.State
		binary.LittleEndian.PutUint64(connBuf[40:48], conn.FirstPacket)
		binary.LittleEndian.PutUint64(connBuf[48:56], conn.LastPacket)
		binary.LittleEndian.PutUint32(connBuf[56:60], conn.PacketCount)
		binary.LittleEndian.PutUint64(connBuf[60:68], conn.ByteCount)

		if _, err := w.Write(connBuf); err != nil {
			return fmt.Errorf("write connection entry: %w", err)
		}
	}

	return nil
}
