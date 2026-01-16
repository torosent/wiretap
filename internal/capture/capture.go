// Package capture provides live network packet capture functionality.
package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/wiretap/wiretap/internal/model"
)

// Common errors
var (
	ErrCaptureRunning    = errors.New("capture already running")
	ErrCaptureNotRunning = errors.New("capture not running")
	ErrInvalidInterface  = errors.New("invalid interface")
)

// LivePacketHandler is called for each captured packet during live capture.
type LivePacketHandler func(*model.Packet)

// CaptureOptions configures packet capture.
type CaptureOptions struct {
	Interface   string
	Promiscuous bool
	SnapLen     int32
	Timeout     time.Duration
	BPFFilter   string
	// TLS decryption options
	TLSDecrypt    bool
	TLSKeyLogFile string
	// gRPC protobuf options
	GRPCProtoDirs  []string
	GRPCProtoFiles []string
}

// DefaultCaptureOptions returns default capture options.
func DefaultCaptureOptions() *CaptureOptions {
	return &CaptureOptions{
		Promiscuous: true,
		SnapLen:     65535,
		Timeout:     pcap.BlockForever,
	}
}

// Capture manages live packet capture.
type Capture struct {
	mu       sync.Mutex
	handle   *pcap.Handle
	opts     *CaptureOptions
	running  bool
	handler  LivePacketHandler
	cancel   context.CancelFunc
	done     chan struct{}
	stats    CaptureStats
	openLive func(device string, snaplen int32, promisc bool, timeout time.Duration) (*pcap.Handle, error)
}

// CaptureStats holds capture statistics.
type CaptureStats struct {
	PacketsReceived  uint64
	PacketsDropped   uint64
	PacketsIfDropped uint64
	BytesReceived    uint64
	StartTime        time.Time
	EndTime          time.Time
}

// Interface represents a network interface.
type Interface struct {
	Name        string
	Description string
	Addresses   []InterfaceAddress
	Flags       uint32
}

// InterfaceAddress represents an address on an interface.
type InterfaceAddress struct {
	IP      string
	Netmask string
}

// NewCapture creates a new capture instance.
func NewCapture(opts *CaptureOptions) *Capture {
	if opts == nil {
		opts = DefaultCaptureOptions()
	}
	return &Capture{
		opts:     opts,
		openLive: pcap.OpenLive,
	}
}

// SetHandler sets the packet handler callback.
func (c *Capture) SetHandler(h LivePacketHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handler = h
}

// Start begins capturing packets.
func (c *Capture) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return ErrCaptureRunning
	}

	openLive := c.openLive
	if openLive == nil {
		openLive = pcap.OpenLive
	}

	handle, err := openLive(
		c.opts.Interface,
		c.opts.SnapLen,
		c.opts.Promiscuous,
		c.opts.Timeout,
	)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("open interface %s: %w", c.opts.Interface, err)
	}

	if c.opts.BPFFilter != "" {
		if err := handle.SetBPFFilter(c.opts.BPFFilter); err != nil {
			handle.Close()
			c.mu.Unlock()
			return fmt.Errorf("set BPF filter: %w", err)
		}
	}

	c.handle = handle
	c.running = true
	c.stats = CaptureStats{StartTime: time.Now()}
	c.done = make(chan struct{})

	ctx, c.cancel = context.WithCancel(ctx)
	c.mu.Unlock()

	go c.captureLoop(ctx)

	return nil
}

// captureLoop reads packets from the interface.
func (c *Capture) captureLoop(ctx context.Context) {
	defer close(c.done)

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	packetSource.NoCopy = true
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			c.processPacket(packet)
		}
	}
}

// processPacket converts a gopacket to our model and calls the handler.
func (c *Capture) processPacket(gp gopacket.Packet) {
	c.mu.Lock()
	handler := c.handler
	c.stats.PacketsReceived++
	c.stats.BytesReceived += uint64(len(gp.Data()))
	c.mu.Unlock()

	if handler == nil {
		return
	}

	pkt := parsePacket(gp)
	if pkt != nil {
		handler(pkt)
	}
}

// parsePacket converts a gopacket.Packet to model.Packet.
func parsePacket(gp gopacket.Packet) *model.Packet {
	pkt := &model.Packet{
		Timestamp:  gp.Metadata().Timestamp,
		Length:     uint32(len(gp.Data())),
		CaptureLen: uint32(gp.Metadata().CaptureLength),
		Data:       gp.Data(),
	}

	// Parse ARP early
	if arpLayer := gp.Layer(layers.LayerTypeARP); arpLayer != nil {
		if arp, ok := arpLayer.(*layers.ARP); ok {
			pkt.Protocol = model.ProtocolARP
			pkt.SrcIP = net.IP(arp.SourceProtAddress)
			pkt.DstIP = net.IP(arp.DstProtAddress)
			switch arp.Operation {
			case layers.ARPRequest:
				pkt.AppInfo = "ARP Request"
			case layers.ARPReply:
				pkt.AppInfo = "ARP Reply"
			}
		}
		return pkt
	}

	// Parse network layer
	if networkLayer := gp.NetworkLayer(); networkLayer != nil {
		switch nl := networkLayer.(type) {
		case *layers.IPv4:
			pkt.SrcIP = nl.SrcIP
			pkt.DstIP = nl.DstIP
			pkt.Protocol = model.Protocol(nl.Protocol)
			pkt.TTL = nl.TTL
		case *layers.IPv6:
			pkt.SrcIP = nl.SrcIP
			pkt.DstIP = nl.DstIP
			pkt.Protocol = model.Protocol(nl.NextHeader)
			pkt.TTL = nl.HopLimit
		}
	}

	// Parse transport layer
	if transportLayer := gp.TransportLayer(); transportLayer != nil {
		switch tl := transportLayer.(type) {
		case *layers.TCP:
			pkt.SrcPort = uint16(tl.SrcPort)
			pkt.DstPort = uint16(tl.DstPort)
			pkt.Protocol = model.ProtocolTCP
			pkt.TCPFlags = model.TCPFlags{
				SYN: tl.SYN,
				ACK: tl.ACK,
				FIN: tl.FIN,
				RST: tl.RST,
				PSH: tl.PSH,
				URG: tl.URG,
				ECE: tl.ECE,
				CWR: tl.CWR,
				NS:  tl.NS,
			}
			pkt.SeqNum = tl.Seq
			pkt.AckNum = tl.Ack
		case *layers.UDP:
			pkt.SrcPort = uint16(tl.SrcPort)
			pkt.DstPort = uint16(tl.DstPort)
			pkt.Protocol = model.ProtocolUDP
		}
	}

	// Parse ICMP
	if icmpLayer := gp.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		if icmp, ok := icmpLayer.(*layers.ICMPv4); ok {
			pkt.Protocol = model.ProtocolICMP
			pkt.AppInfo = fmt.Sprintf("ICMP type=%d code=%d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
		}
	}
	if icmpLayer := gp.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		if icmp, ok := icmpLayer.(*layers.ICMPv6); ok {
			pkt.Protocol = model.ProtocolICMPv6
			pkt.AppInfo = fmt.Sprintf("ICMPv6 type=%d code=%d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
		}
	}

	// Store application layer payload
	if appLayer := gp.ApplicationLayer(); appLayer != nil {
		pkt.Payload = appLayer.Payload()
	}

	return pkt
}

// Stop stops packet capture.
func (c *Capture) Stop() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return ErrCaptureNotRunning
	}

	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()

	// Wait for capture loop to exit
	<-c.done

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.handle != nil {
		stats, _ := c.handle.Stats()
		if stats != nil {
			c.stats.PacketsDropped = uint64(stats.PacketsDropped)
			c.stats.PacketsIfDropped = uint64(stats.PacketsIfDropped)
		}
		c.handle.Close()
		c.handle = nil
	}

	c.running = false
	c.stats.EndTime = time.Now()

	return nil
}

// Stats returns capture statistics.
func (c *Capture) Stats() CaptureStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// IsRunning returns whether capture is active.
func (c *Capture) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// ListInterfaces returns all available network interfaces.
func ListInterfaces() ([]Interface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find interfaces: %w", err)
	}

	interfaces := make([]Interface, len(devs))
	for i, dev := range devs {
		iface := Interface{
			Name:        dev.Name,
			Description: dev.Description,
			Flags:       dev.Flags,
		}

		for _, addr := range dev.Addresses {
			iface.Addresses = append(iface.Addresses, InterfaceAddress{
				IP:      addr.IP.String(),
				Netmask: addr.Netmask.String(),
			})
		}

		interfaces[i] = iface
	}

	return interfaces, nil
}

// PcapWriter writes captured packets to a pcap file.
type PcapWriter struct {
	mu     sync.Mutex
	file   io.WriteCloser
	writer *pcapgo.Writer
	count  uint64
}

// NewPcapWriter creates a new pcap file writer.
func NewPcapWriter(w io.WriteCloser, linkType layers.LinkType) (*PcapWriter, error) {
	pw := &PcapWriter{
		file: w,
	}

	pw.writer = pcapgo.NewWriter(w)
	if err := pw.writer.WriteFileHeader(65535, linkType); err != nil {
		return nil, fmt.Errorf("write pcap header: %w", err)
	}

	return pw, nil
}

// WritePacket writes a packet to the pcap file.
func (pw *PcapWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	if err := pw.writer.WritePacket(ci, data); err != nil {
		return fmt.Errorf("write packet: %w", err)
	}

	pw.count++
	return nil
}

// Count returns the number of packets written.
func (pw *PcapWriter) Count() uint64 {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	return pw.count
}

// Close closes the pcap writer.
func (pw *PcapWriter) Close() error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.file != nil {
		return pw.file.Close()
	}
	return nil
}

// FindInterfaceByName returns an interface by name.
func FindInterfaceByName(name string) (*Interface, error) {
	interfaces, err := ListInterfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Name == name {
			return &iface, nil
		}
	}

	return nil, ErrInvalidInterface
}
