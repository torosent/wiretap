// Package capture provides pcap file reading functionality.
package capture

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/wiretap/wiretap/internal/model"
)

// Common errors.
var (
	ErrInvalidPcapFile   = errors.New("invalid pcap file")
	ErrUnsupportedFormat = errors.New("unsupported file format")
)

// PacketHandler is called for each packet read from a file.
type PacketHandler func(*model.Packet) error

// PcapReader reads packets from pcap/pcapng files.
type PcapReader struct {
	path       string
	file       *os.File
	handle     *pcap.Handle
	ngReader   *pcapgo.NgReader
	pcapReader *pcapgo.Reader
	linkType   layers.LinkType
	isPcapng   bool
}

// OpenPcap opens a pcap or pcapng file for reading.
func OpenPcap(path string) (*PcapReader, error) {
	// Check file exists
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if info.IsDir() {
		return nil, errors.New("path is a directory")
	}

	// Determine format from extension
	ext := strings.ToLower(filepath.Ext(path))
	isPcapng := ext == ".pcapng"

	// Open file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	reader := &PcapReader{
		path:     path,
		file:     file,
		isPcapng: isPcapng,
	}

	// Try to open as pcapng first, then pcap
	if isPcapng {
		ngReader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to open pcapng: %w", err)
		}
		reader.ngReader = ngReader
		reader.linkType = ngReader.LinkType()
	} else {
		// Try gopacket pcap reader first (doesn't require libpcap for reading)
		pcapReader, err := pcapgo.NewReader(file)
		if err != nil {
			// Fall back to pcap handle
			file.Close()
			reader.file = nil
			handle, err := pcap.OpenOffline(path)
			if err != nil {
				return nil, fmt.Errorf("failed to open pcap: %w", err)
			}
			reader.handle = handle
			reader.linkType = handle.LinkType()
		} else {
			reader.pcapReader = pcapReader
			reader.linkType = pcapReader.LinkType()
		}
	}

	return reader, nil
}

// LinkType returns the link type of the capture.
func (r *PcapReader) LinkType() layers.LinkType {
	return r.linkType
}

// Path returns the file path.
func (r *PcapReader) Path() string {
	return r.path
}

// IsPcapng returns true if the capture file is pcapng.
func (r *PcapReader) IsPcapng() bool {
	return r.isPcapng
}

// ReadPacket reads the next packet from the file.
func (r *PcapReader) ReadPacket() (gopacket.CaptureInfo, []byte, error) {
	if r.ngReader != nil {
		data, ci, err := r.ngReader.ReadPacketData()
		return ci, data, err
	}

	if r.pcapReader != nil {
		data, ci, err := r.pcapReader.ReadPacketData()
		return ci, data, err
	}

	if r.handle != nil {
		data, ci, err := r.handle.ReadPacketData()
		return ci, data, err
	}

	return gopacket.CaptureInfo{}, nil, errors.New("no reader available")
}

// ReadAll reads all packets from the file and calls the handler for each.
func (r *PcapReader) ReadAll(handler PacketHandler) error {
	var index uint64

	for {
		ci, data, err := r.ReadPacket()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		index++

		// Parse packet
		rawPacket := gopacket.NewPacket(data, r.linkType, gopacket.Default)

		// Set metadata
		meta := rawPacket.Metadata()
		meta.Timestamp = ci.Timestamp
		meta.CaptureLength = ci.CaptureLength
		meta.Length = ci.Length

		pkt := parsePacket(rawPacket)
		pkt.Index = index
		pkt.FileOffset = -1 // Not tracking offset in simple read

		if handler != nil {
			if err := handler(pkt); err != nil {
				return err
			}
		}
	}
}

// ReadAllWithOffset reads all packets and tracks file offsets.
func (r *PcapReader) ReadAllWithOffset(handler func(*model.Packet, int64) error) error {
	// This requires a more complex implementation that tracks file position
	// For now, use ReadAll which doesn't track offsets
	return r.ReadAll(func(pkt *model.Packet) error {
		return handler(pkt, -1)
	})
}

// Close closes the reader.
func (r *PcapReader) Close() error {
	if r.handle != nil {
		r.handle.Close()
	}
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// PacketIterator provides iterator-style access to packets.
type PacketIterator struct {
	reader *PcapReader
	index  uint64
	err    error
}

// NewPacketIterator creates a new packet iterator.
func NewPacketIterator(reader *PcapReader) *PacketIterator {
	return &PacketIterator{
		reader: reader,
	}
}

// Next reads the next packet.
func (it *PacketIterator) Next() (*model.Packet, bool) {
	ci, data, err := it.reader.ReadPacket()
	if err != nil {
		if err != io.EOF {
			it.err = err
		}
		return nil, false
	}

	it.index++

	rawPacket := gopacket.NewPacket(data, it.reader.linkType, gopacket.Default)
	meta := rawPacket.Metadata()
	meta.Timestamp = ci.Timestamp
	meta.CaptureLength = ci.CaptureLength
	meta.Length = ci.Length

	pkt := parsePacket(rawPacket)
	pkt.Index = it.index

	return pkt, true
}

// Error returns any error encountered during iteration.
func (it *PacketIterator) Error() error {
	return it.err
}

// Count returns the number of packets read so far.
func (it *PacketIterator) Count() uint64 {
	return it.index
}

// GetFileInfo returns information about a pcap file without reading all packets.
func GetFileInfo(path string) (*PcapFileInfo, error) {
	reader, err := OpenPcap(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	info := &PcapFileInfo{
		Path:     path,
		LinkType: reader.LinkType(),
	}

	// Get file size
	if stat, err := os.Stat(path); err == nil {
		info.FileSize = stat.Size()
	}

	// Count packets (this reads the whole file)
	var count uint64
	for {
		_, _, err := reader.ReadPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		count++
	}

	info.PacketCount = count

	return info, nil
}

// PcapFileInfo contains information about a pcap file.
type PcapFileInfo struct {
	Path        string
	FileSize    int64
	PacketCount uint64
	LinkType    layers.LinkType
}
