// Package index provides index building functionality.
package index

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/wiretap/wiretap/internal/capture"
	"github.com/wiretap/wiretap/internal/model"
)

// Builder builds packet index files.
type Builder struct {
	pcapPath  string
	indexPath string
	file      *os.File
	packets   uint64
	conns     uint64
	fileSize  int64
	createdAt int64

	// Connection tracking
	connections map[uint64]*connectionInfo
	connList    []*connectionInfo
}

// connectionInfo tracks connection metadata during indexing.
type connectionInfo struct {
	id          uint32
	srcIP       [16]byte
	dstIP       [16]byte
	srcPort     uint16
	dstPort     uint16
	protocol    uint16
	isIPv6      bool
	state       uint8
	firstPacket uint64
	lastPacket  uint64
	packetCount uint32
	byteCount   uint64
	startTime   int64
	endTime     int64
}

// NewBuilder creates a new index builder.
func NewBuilder(pcapPath, indexPath string) *Builder {
	return &Builder{
		pcapPath:    pcapPath,
		indexPath:   indexPath,
		connections: make(map[uint64]*connectionInfo),
		connList:    make([]*connectionInfo, 0),
		createdAt:   time.Now().Unix(),
	}
}

// Build builds the index for a pcap file.
func (b *Builder) Build() error {
	// Open pcap file
	reader, err := capture.OpenPcap(b.pcapPath)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer reader.Close()

	// Get pcap file size
	info, err := os.Stat(b.pcapPath)
	if err != nil {
		return fmt.Errorf("failed to stat pcap: %w", err)
	}
	b.fileSize = info.Size()

	// Create index file
	b.file, err = os.Create(b.indexPath)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	defer b.file.Close()

	// Write placeholder header (will update at end)
	if err := b.writeHeader(); err != nil {
		return err
	}

	// Index all packets
	if err := b.indexPackets(reader); err != nil {
		return err
	}

	// Write connection index
	if err := b.writeConnections(); err != nil {
		return err
	}

	// Update header with final counts
	if err := b.updateHeader(); err != nil {
		return err
	}

	return nil
}

// writeHeader writes the index header.
func (b *Builder) writeHeader() error {
	header := make([]byte, HeaderSize)

	binary.LittleEndian.PutUint32(header[0:4], MagicNumber)
	binary.LittleEndian.PutUint32(header[4:8], CurrentVersion)
	binary.LittleEndian.PutUint64(header[8:16], 0) // packet count
	binary.LittleEndian.PutUint64(header[16:24], 0) // connection count
	binary.LittleEndian.PutUint64(header[24:32], uint64(b.createdAt))
	binary.LittleEndian.PutUint64(header[32:40], uint64(b.fileSize))

	_, err := b.file.Write(header)
	return err
}

// updateHeader updates the header with final values.
func (b *Builder) updateHeader() error {
	header := make([]byte, HeaderSize)

	binary.LittleEndian.PutUint32(header[0:4], MagicNumber)
	binary.LittleEndian.PutUint32(header[4:8], CurrentVersion)
	binary.LittleEndian.PutUint64(header[8:16], b.packets)
	binary.LittleEndian.PutUint64(header[16:24], b.conns)
	binary.LittleEndian.PutUint64(header[24:32], uint64(b.createdAt))
	binary.LittleEndian.PutUint64(header[32:40], uint64(b.fileSize))

	// Seek to beginning and write
	if _, err := b.file.Seek(0, 0); err != nil {
		return err
	}

	_, err := b.file.Write(header)
	return err
}

// indexPackets indexes all packets from the pcap.
func (b *Builder) indexPackets(reader *capture.PcapReader) error {
	var fileOffset int64 = 24 // Skip global header (24 bytes for pcap)

	for {
		ci, data, err := reader.ReadPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		b.packets++

		// Parse packet
		rawPacket := gopacket.NewPacket(data, reader.LinkType(), gopacket.Lazy)
		pkt := b.parsePacketForIndex(rawPacket, ci, b.packets)

		// Track connection
		conn := b.trackConnection(pkt)

		// Write packet entry
		if err := b.writePacketEntry(pkt, fileOffset, conn); err != nil {
			return err
		}

		// Update file offset (16 byte packet header + data)
		fileOffset += 16 + int64(ci.CaptureLength)
	}

	return nil
}

// parsePacketForIndex extracts minimal info needed for indexing.
func (b *Builder) parsePacketForIndex(rawPacket gopacket.Packet, ci gopacket.CaptureInfo, index uint64) *model.Packet {
	pkt := &model.Packet{
		Index:       index,
		Timestamp:   ci.Timestamp,
		CapturedLen: uint32(ci.CaptureLength),
		OriginalLen: uint32(ci.Length),
	}

	// Extract network layer
	if ipLayer := rawPacket.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		pkt.SrcIP = ip.SrcIP
		pkt.DstIP = ip.DstIP
		pkt.Protocol = model.ProtocolIPv4
	} else if ipLayer := rawPacket.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		pkt.SrcIP = ip.SrcIP
		pkt.DstIP = ip.DstIP
		pkt.Protocol = model.ProtocolIPv6
	}

	// Extract transport layer
	if tcpLayer := rawPacket.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		pkt.SrcPort = uint16(tcp.SrcPort)
		pkt.DstPort = uint16(tcp.DstPort)
		pkt.Protocol = model.ProtocolTCP

		// TCP flags
		pkt.TCPFlags = model.TCPFlags{
			FIN: tcp.FIN,
			SYN: tcp.SYN,
			RST: tcp.RST,
			PSH: tcp.PSH,
			ACK: tcp.ACK,
			URG: tcp.URG,
			ECE: tcp.ECE,
			CWR: tcp.CWR,
			NS:  tcp.NS,
		}
	} else if udpLayer := rawPacket.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		pkt.SrcPort = uint16(udp.SrcPort)
		pkt.DstPort = uint16(udp.DstPort)
		pkt.Protocol = model.ProtocolUDP
	}

	if icmpLayer := rawPacket.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		pkt.Protocol = model.ProtocolICMP
	}
	if icmpLayer := rawPacket.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		pkt.Protocol = model.ProtocolICMPv6
	}

	return pkt
}

// trackConnection tracks connection metadata.
func (b *Builder) trackConnection(pkt *model.Packet) *connectionInfo {
	if pkt.Protocol != model.ProtocolTCP && pkt.Protocol != model.ProtocolUDP {
		return nil
	}

	hash := pkt.FlowHash()
	ts := pkt.Timestamp.UnixNano()

	conn, ok := b.connections[hash]
	if !ok {
		isIPv6 := pkt.SrcIP != nil && pkt.SrcIP.To4() == nil
		srcIP := model.IPToBytes(pkt.SrcIP)
		dstIP := model.IPToBytes(pkt.DstIP)

		state := uint8(0)
		if pkt.Protocol == model.ProtocolTCP {
			state = 1
		}

		conn = &connectionInfo{
			id:          uint32(len(b.connList)),
			srcIP:       srcIP,
			dstIP:       dstIP,
			srcPort:     pkt.SrcPort,
			dstPort:     pkt.DstPort,
			protocol:    uint16(pkt.Protocol),
			isIPv6:      isIPv6,
			state:       state,
			firstPacket: pkt.Index,
			startTime:   ts,
		}
		b.connections[hash] = conn
		b.connList = append(b.connList, conn)
	}

	conn.lastPacket = pkt.Index
	conn.packetCount++
	conn.byteCount += uint64(pkt.CapturedLen)
	conn.endTime = ts

	return conn
}

// writePacketEntry writes a single packet entry.
func (b *Builder) writePacketEntry(pkt *model.Packet, fileOffset int64, conn *connectionInfo) error {
	entry := make([]byte, PacketEntrySize)

	length := pkt.OriginalLen
	if length == 0 {
		length = pkt.CapturedLen
	}

	binary.LittleEndian.PutUint64(entry[0:8], uint64(fileOffset))
	binary.LittleEndian.PutUint32(entry[8:12], length)
	binary.LittleEndian.PutUint64(entry[12:20], uint64(pkt.Timestamp.UnixNano()))
	binary.LittleEndian.PutUint16(entry[20:22], uint16(pkt.Protocol))
	binary.LittleEndian.PutUint16(entry[22:24], uint16(pkt.TCPFlags.ToUint8()))
	if conn != nil {
		binary.LittleEndian.PutUint32(entry[24:28], conn.id)
	}
	binary.LittleEndian.PutUint16(entry[28:30], pkt.SrcPort)
	binary.LittleEndian.PutUint16(entry[30:32], pkt.DstPort)

	_, err := b.file.Write(entry)
	return err
}

// writeConnections writes the connection index.
func (b *Builder) writeConnections() error {
	for _, conn := range b.connList {
		entry := make([]byte, ConnectionEntrySize)

		copy(entry[0:16], conn.srcIP[:])
		copy(entry[16:32], conn.dstIP[:])
		binary.LittleEndian.PutUint16(entry[32:34], conn.srcPort)
		binary.LittleEndian.PutUint16(entry[34:36], conn.dstPort)
		binary.LittleEndian.PutUint16(entry[36:38], conn.protocol)
		if conn.isIPv6 {
			entry[38] = 1
		}
		entry[39] = conn.state
		binary.LittleEndian.PutUint64(entry[40:48], conn.firstPacket)
		binary.LittleEndian.PutUint64(entry[48:56], conn.lastPacket)
		binary.LittleEndian.PutUint32(entry[56:60], conn.packetCount)
		binary.LittleEndian.PutUint64(entry[60:68], conn.byteCount)

		if _, err := b.file.Write(entry); err != nil {
			return err
		}

		b.conns++
	}

	return nil
}

// Progress returns the current progress of indexing.
func (b *Builder) Progress() (packets uint64, connections int) {
	return b.packets, len(b.connList)
}

// BuildProgress tracks indexing progress.
type BuildProgress struct {
	PacketsProcessed uint64
	ConnectionsFound int
	StartTime        time.Time
	Finished         bool
	Error            error
}

// BuildAsync builds the index asynchronously with progress reporting.
func BuildAsync(pcapPath, indexPath string, progress chan<- BuildProgress) {
	builder := NewBuilder(pcapPath, indexPath)
	startTime := time.Now()

	defer close(progress)

	// Report initial state
	progress <- BuildProgress{StartTime: startTime}

	// TODO: Implement incremental progress reporting
	// For now, just build synchronously

	err := builder.Build()

	progress <- BuildProgress{
		PacketsProcessed: builder.packets,
		ConnectionsFound: len(builder.connections),
		StartTime:        startTime,
		Finished:         true,
		Error:            err,
	}
}
