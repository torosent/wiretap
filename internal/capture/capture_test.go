package capture

import (
	"testing"
	"time"
)

func TestDefaultCaptureOptions(t *testing.T) {
	opts := DefaultCaptureOptions()

	if opts == nil {
		t.Fatal("DefaultCaptureOptions returned nil")
	}

	if !opts.Promiscuous {
		t.Error("Promiscuous should be true by default")
	}

	if opts.SnapLen != 65535 {
		t.Errorf("SnapLen = %d, want 65535", opts.SnapLen)
	}
}

func TestNewCapture(t *testing.T) {
	c := NewCapture(nil)
	if c == nil {
		t.Fatal("NewCapture returned nil")
	}

	if c.opts == nil {
		t.Error("opts should not be nil")
	}
	if !c.opts.Promiscuous {
		t.Error("Default opts.Promiscuous should be true")
	}
}

func TestNewCapture_WithOptions(t *testing.T) {
	opts := &CaptureOptions{
		Interface:   "eth0",
		Promiscuous: false,
		SnapLen:     1500,
		Timeout:     time.Second,
		BPFFilter:   "tcp port 80",
	}

	c := NewCapture(opts)

	if c.opts.Interface != "eth0" {
		t.Errorf("Interface = %s, want eth0", c.opts.Interface)
	}
	if c.opts.Promiscuous {
		t.Error("Promiscuous should be false")
	}
	if c.opts.SnapLen != 1500 {
		t.Errorf("SnapLen = %d, want 1500", c.opts.SnapLen)
	}
	if c.opts.BPFFilter != "tcp port 80" {
		t.Errorf("BPFFilter = %s, want 'tcp port 80'", c.opts.BPFFilter)
	}
}

func TestCapture_IsRunning(t *testing.T) {
	c := NewCapture(nil)

	if c.IsRunning() {
		t.Error("Capture should not be running initially")
	}
}

func TestCapture_Stats(t *testing.T) {
	c := NewCapture(nil)

	stats := c.Stats()

	if stats.PacketsReceived != 0 {
		t.Errorf("PacketsReceived = %d, want 0", stats.PacketsReceived)
	}
	if stats.BytesReceived != 0 {
		t.Errorf("BytesReceived = %d, want 0", stats.BytesReceived)
	}
}

func TestCapture_Stop_NotRunning(t *testing.T) {
	c := NewCapture(nil)

	err := c.Stop()
	if err != ErrCaptureNotRunning {
		t.Errorf("Expected ErrCaptureNotRunning, got %v", err)
	}
}

func TestCaptureStats_Duration(t *testing.T) {
	now := time.Now()
	stats := CaptureStats{
		StartTime: now,
		EndTime:   now.Add(5 * time.Second),
	}

	duration := stats.EndTime.Sub(stats.StartTime)
	if duration != 5*time.Second {
		t.Errorf("Duration = %v, want 5s", duration)
	}
}

func TestInterface_String(t *testing.T) {
	iface := Interface{
		Name:        "eth0",
		Description: "Ethernet adapter",
		Addresses: []InterfaceAddress{
			{IP: "192.168.1.100", Netmask: "255.255.255.0"},
		},
	}

	if iface.Name != "eth0" {
		t.Errorf("Name = %s, want eth0", iface.Name)
	}
	if len(iface.Addresses) != 1 {
		t.Errorf("Addresses count = %d, want 1", len(iface.Addresses))
	}
	if iface.Addresses[0].IP != "192.168.1.100" {
		t.Errorf("Address IP = %s, want 192.168.1.100", iface.Addresses[0].IP)
	}
}

// Note: Live capture tests require root/admin privileges and actual network interfaces.
// These tests focus on unit testing the capture logic without actual packet capture.
// Integration tests should be run separately with appropriate permissions.
