package cli

import (
	"context"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/wiretap/wiretap/internal/capture"
	"github.com/wiretap/wiretap/internal/model"
)

func newCaptureTestCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("interface", "", "")
	cmd.Flags().String("filter", "", "")
	cmd.Flags().String("write", "", "")
	cmd.Flags().Int("count", 0, "")
	cmd.Flags().Int("snaplen", 65535, "")
	cmd.Flags().Duration("timeout", 0, "")
	cmd.Flags().Bool("promisc", true, "")
	cmd.Flags().Bool("stats", false, "")
	cmd.Flags().Bool("verbose", false, "")
	return cmd
}

func TestRunCapture_InvalidInterface(t *testing.T) {
	cmd := newCaptureTestCommand()
	cmd.Flags().Set("interface", "invalid0")
	cmd.Flags().Set("count", "1")

	if err := runCapture(cmd, nil); err == nil {
		t.Fatal("Expected error for invalid interface")
	}
}

type stubCapture struct {
	handler capture.LivePacketHandler
	stats   capture.CaptureStats
}

func (s *stubCapture) SetHandler(h capture.LivePacketHandler) {
	s.handler = h
}

func (s *stubCapture) Start(ctx context.Context) error {
	if s.handler != nil {
		s.handler(&model.Packet{
			Timestamp:  time.Now(),
			Length:     60,
			CaptureLen: 60,
			Data:       []byte("payload"),
		})
	}
	return nil
}

func (s *stubCapture) Stop() error {
	return nil
}

func (s *stubCapture) Stats() capture.CaptureStats {
	return s.stats
}

func TestRunCapture_WithStub(t *testing.T) {
	cmd := newCaptureTestCommand()
	cmd.Flags().Set("interface", "stub0")
	cmd.Flags().Set("count", "1")
	cmd.Flags().Set("stats", "true")

	orig := newLiveCapture
	newLiveCapture = func(opts *capture.CaptureOptions) liveCapture {
		return &stubCapture{stats: capture.CaptureStats{PacketsReceived: 1}}
	}
	t.Cleanup(func() { newLiveCapture = orig })

	if err := runCapture(cmd, nil); err != nil {
		t.Fatalf("runCapture failed: %v", err)
	}
}
