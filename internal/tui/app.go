// Package tui provides a terminal user interface for wiretap.
package tui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/wiretap/wiretap/internal/capture"
	"github.com/wiretap/wiretap/internal/model"
	"github.com/wiretap/wiretap/internal/protocol"
)

// App represents the TUI application.
type App struct {
	app         *tview.Application
	pages       *tview.Pages
	registry    *protocol.DissectorRegistry
	queueUpdate func(func())
	run         func() error

	// Main layout
	packetList  *tview.Table
	detailTree  *tview.TreeView
	hexView     *tview.TextView
	statusBar   *tview.TextView
	filterInput *tview.InputField
	rightPanel  *tview.Flex
	mainContent *tview.Flex

	// State
	packets     []*model.Packet
	filteredIdx []int
	selectedIdx int
	filter      string
	showHex     bool
	mu          sync.RWMutex

	// Capture state
	captureActive bool
	capturer      *capture.Capture
	pcapFile      string
}

// New creates a new TUI application.
func New() *App {
	a := &App{
		app:      tview.NewApplication(),
		pages:    tview.NewPages(),
		registry: protocol.NewRegistry(),
		packets:  make([]*model.Packet, 0),
		showHex:  true,
	}

	a.queueUpdate = func(fn func()) {
		a.app.QueueUpdateDraw(fn)
	}
	a.run = a.app.Run

	a.setupUI()
	return a
}

func (a *App) setupUI() {
	// Create packet list table
	a.packetList = tview.NewTable().
		SetSelectable(true, false).
		SetFixed(1, 0).
		SetSeparator(tview.Borders.Vertical)

	a.packetList.SetBorder(true).SetTitle(" Packets ")
	a.setupPacketListHeader()

	// Handle packet selection
	a.packetList.SetSelectionChangedFunc(func(row, col int) {
		if row > 0 {
			a.onPacketSelected(row - 1)
		}
	})

	// Create detail tree view
	root := tview.NewTreeNode("Packet Details")
	a.detailTree = tview.NewTreeView().SetRoot(root)
	a.detailTree.SetBorder(true).SetTitle(" Details ")

	// Create hex view
	a.hexView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	a.hexView.SetBorder(true).SetTitle(" Hex Dump ")

	// Create status bar
	a.statusBar = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	a.updateStatus("Ready")

	// Create filter input
	a.filterInput = tview.NewInputField().
		SetLabel("Filter: ").
		SetFieldWidth(50).
		SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEnter {
				a.applyFilter(a.filterInput.GetText())
				a.app.SetFocus(a.packetList)
			} else if key == tcell.KeyEscape {
				a.filterInput.SetText(a.filter)
				a.app.SetFocus(a.packetList)
			}
		})

	// Create right panel (details + hex)
	a.rightPanel = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.detailTree, 0, 1, false).
		AddItem(a.hexView, 0, 1, false)

	// Create main content area
	a.mainContent = tview.NewFlex().
		AddItem(a.packetList, 0, 1, true).
		AddItem(a.rightPanel, 0, 1, false)

	// Create top bar with filter
	topBar := tview.NewFlex().
		AddItem(a.filterInput, 0, 1, false)

	// Create main layout
	mainLayout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(topBar, 1, 0, false).
		AddItem(a.mainContent, 0, 1, true).
		AddItem(a.statusBar, 1, 0, false)

	a.pages.AddPage("main", mainLayout, true, true)

	// Set up key bindings
	a.setupKeyBindings()
}

func (a *App) setupPacketListHeader() {
	headers := []string{"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"}
	for i, h := range headers {
		cell := tview.NewTableCell(h).
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false).
			SetExpansion(1)
		a.packetList.SetCell(0, i, cell)
	}
}

func (a *App) setupKeyBindings() {
	a.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyF1:
			a.showHelp()
			return nil
		case tcell.KeyF5:
			a.refreshPacketList()
			return nil
		case tcell.KeyCtrlC:
			a.app.Stop()
			return nil
		case tcell.KeyCtrlF:
			a.app.SetFocus(a.filterInput)
			return nil
		case tcell.KeyTab:
			a.focusNextPane()
			return nil
		case tcell.KeyEscape:
			if a.app.GetFocus() == a.filterInput {
				a.app.SetFocus(a.packetList)
				return nil
			}
		}

		// Handle vim-style navigation
		switch event.Rune() {
		case 'q':
			a.app.Stop()
			return nil
		case '?':
			a.showHelp()
			return nil
		case '/':
			a.app.SetFocus(a.filterInput)
			return nil
		case 'f':
			a.showFollowTCPStream()
			return nil
		case 'h':
			a.toggleHexView()
			return nil
		case 'j':
			return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
		case 'k':
			return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
		case 'g':
			a.packetList.Select(1, 0)
			return nil
		case 'G':
			a.packetList.Select(a.packetList.GetRowCount()-1, 0)
			return nil
		}

		return event
	})
}

func (a *App) onPacketSelected(idx int) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if idx < 0 || idx >= len(a.filteredIdx) {
		return
	}

	packetIdx := a.filteredIdx[idx]
	if packetIdx >= len(a.packets) {
		return
	}

	pkt := a.packets[packetIdx]
	a.selectedIdx = idx

	// Update detail tree
	a.updateDetailTree(pkt)

	// Update hex view
	a.updateHexView(pkt)
}

func (a *App) updateDetailTree(pkt *model.Packet) {
	root := tview.NewTreeNode("Packet Details").SetColor(tcell.ColorWhite)

	// Frame info
	frameNode := tview.NewTreeNode("Frame").SetColor(tcell.ColorGreen)
	frameNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Arrival Time: %s", pkt.Timestamp.Format("2006-01-02 15:04:05.000000"))))
	frameNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Frame Length: %d bytes", pkt.OriginalLen)))
	frameNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Capture Length: %d bytes", pkt.CapturedLen)))
	root.AddChild(frameNode)

	// IP info
	if pkt.SrcIP != nil {
		ipNode := tview.NewTreeNode("Internet Protocol").SetColor(tcell.ColorGreen)
		ipNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Source: %s", pkt.SrcIP)))
		ipNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Destination: %s", pkt.DstIP)))
		root.AddChild(ipNode)
	}

	// Transport info
	switch pkt.Protocol {
	case model.ProtocolTCP:
		tcpNode := tview.NewTreeNode("Transmission Control Protocol").SetColor(tcell.ColorGreen)
		tcpNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Source Port: %d", pkt.SrcPort)))
		tcpNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Destination Port: %d", pkt.DstPort)))
		tcpNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Flags: %s", pkt.TCPFlags.String())))
		root.AddChild(tcpNode)

	case model.ProtocolUDP:
		udpNode := tview.NewTreeNode("User Datagram Protocol").SetColor(tcell.ColorGreen)
		udpNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Source Port: %d", pkt.SrcPort)))
		udpNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Destination Port: %d", pkt.DstPort)))
		udpNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Length: %d", len(pkt.Payload))))
		root.AddChild(udpNode)
	case model.ProtocolICMP:
		icmpNode := tview.NewTreeNode("Internet Control Message Protocol").SetColor(tcell.ColorGreen)
		if pkt.AppInfo != "" {
			icmpNode.AddChild(tview.NewTreeNode(pkt.AppInfo))
		}
		root.AddChild(icmpNode)
	case model.ProtocolICMPv6:
		icmpNode := tview.NewTreeNode("Internet Control Message Protocol v6").SetColor(tcell.ColorGreen)
		if pkt.AppInfo != "" {
			icmpNode.AddChild(tview.NewTreeNode(pkt.AppInfo))
		}
		root.AddChild(icmpNode)
	case model.ProtocolARP:
		arpNode := tview.NewTreeNode("Address Resolution Protocol").SetColor(tcell.ColorGreen)
		arpNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Source: %s", pkt.SrcIP)))
		arpNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Destination: %s", pkt.DstIP)))
		if pkt.AppInfo != "" {
			arpNode.AddChild(tview.NewTreeNode(pkt.AppInfo))
		}
		root.AddChild(arpNode)
	}

	// Dissect application layer
	if len(pkt.Payload) > 0 {
		a.registry.Parse(pkt.Payload, pkt)

		if pkt.HTTPInfo != nil {
			httpNode := tview.NewTreeNode("Hypertext Transfer Protocol").SetColor(tcell.ColorGreen)
			if pkt.HTTPInfo.Request != nil {
				httpNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Request: %s %s", pkt.HTTPInfo.Request.Method, pkt.HTTPInfo.Request.URI)))
			}
			if pkt.HTTPInfo.Response != nil {
				httpNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Response: %d %s", pkt.HTTPInfo.Response.StatusCode, pkt.HTTPInfo.Response.StatusText)))
			}
			root.AddChild(httpNode)
		}

		if pkt.TLSInfo != nil {
			tlsNode := tview.NewTreeNode("Transport Layer Security").SetColor(tcell.ColorGreen)
			tlsNode.AddChild(tview.NewTreeNode(fmt.Sprintf("Version: %s", pkt.TLSInfo.Version)))
			if pkt.TLSInfo.SNI() != "" {
				tlsNode.AddChild(tview.NewTreeNode(fmt.Sprintf("SNI: %s", pkt.TLSInfo.SNI())))
			}
			root.AddChild(tlsNode)
		}

		if pkt.DNSInfo != nil {
			dnsNode := tview.NewTreeNode("Domain Name System").SetColor(tcell.ColorGreen)
			if pkt.DNSInfo.IsResponse {
				dnsNode.AddChild(tview.NewTreeNode("Response"))
			} else {
				dnsNode.AddChild(tview.NewTreeNode("Query"))
			}
			root.AddChild(dnsNode)
		}
	}

	a.detailTree.SetRoot(root)
	root.SetExpanded(true)
}

func (a *App) updateHexView(pkt *model.Packet) {
	if len(pkt.Payload) == 0 {
		a.hexView.SetText("No payload data")
		return
	}

	var sb strings.Builder
	data := pkt.Payload

	const bytesPerLine = 16
	for i := 0; i < len(data); i += bytesPerLine {
		// Offset
		sb.WriteString(fmt.Sprintf("[yellow]%04x[white]  ", i))

		// Hex bytes
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}

		for j := i; j < end; j++ {
			sb.WriteString(fmt.Sprintf("%02x ", data[j]))
			if j == i+7 {
				sb.WriteString(" ")
			}
		}

		// Pad if needed
		for j := end; j < i+bytesPerLine; j++ {
			sb.WriteString("   ")
			if j == i+7 {
				sb.WriteString(" ")
			}
		}

		// ASCII
		sb.WriteString(" [green]|")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] < 127 {
				sb.WriteString(string(data[j]))
			} else {
				sb.WriteString(".")
			}
		}
		sb.WriteString("|[white]\n")
	}

	a.hexView.SetText(sb.String())
}

func (a *App) refreshPacketList() {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Clear existing rows (keep header)
	for i := a.packetList.GetRowCount() - 1; i > 0; i-- {
		a.packetList.RemoveRow(i)
	}

	// Get first timestamp for relative time
	var firstTime time.Time
	if len(a.filteredIdx) > 0 {
		firstTime = a.packets[a.filteredIdx[0]].Timestamp
	}

	// Add packets
	for i, idx := range a.filteredIdx {
		pkt := a.packets[idx]
		row := i + 1

		relTime := pkt.Timestamp.Sub(firstTime)

		// Determine row color based on protocol
		color := tcell.ColorWhite
		switch pkt.Protocol {
		case model.ProtocolTCP:
			if pkt.SrcPort == 80 || pkt.DstPort == 80 {
				color = tcell.ColorGreen // HTTP
			} else if pkt.SrcPort == 443 || pkt.DstPort == 443 {
				color = tcell.ColorYellow // HTTPS
			}
		case model.ProtocolUDP:
			if pkt.SrcPort == 53 || pkt.DstPort == 53 {
				color = tcell.ColorAqua // DNS
			}
		}

		// Format info
		info := a.formatPacketInfo(pkt)

		cells := []string{
			fmt.Sprintf("%d", idx+1),
			fmt.Sprintf("%.6f", relTime.Seconds()),
			formatAddr(pkt.SrcIP, pkt.SrcPort),
			formatAddr(pkt.DstIP, pkt.DstPort),
			pkt.Protocol.String(),
			fmt.Sprintf("%d", pkt.CapturedLen),
			info,
		}

		for col, text := range cells {
			cell := tview.NewTableCell(text).
				SetTextColor(color).
				SetExpansion(1)
			a.packetList.SetCell(row, col, cell)
		}
	}

	a.updateStatus(fmt.Sprintf("Displaying %d of %d packets", len(a.filteredIdx), len(a.packets)))
}

func (a *App) formatPacketInfo(pkt *model.Packet) string {
	// Try to dissect
	if len(pkt.Payload) > 0 {
		a.registry.Parse(pkt.Payload, pkt)

		if pkt.HTTPInfo != nil {
			if pkt.HTTPInfo.Request != nil {
				return fmt.Sprintf("%s %s", pkt.HTTPInfo.Request.Method, pkt.HTTPInfo.Request.URI)
			}
			if pkt.HTTPInfo.Response != nil {
				return fmt.Sprintf("%d %s", pkt.HTTPInfo.Response.StatusCode, pkt.HTTPInfo.Response.StatusText)
			}
		}

		if pkt.TLSInfo != nil {
			return fmt.Sprintf("TLS %s", pkt.TLSInfo.Version)
		}

		if pkt.DNSInfo != nil {
			if pkt.DNSInfo.IsResponse {
				return "DNS Response"
			}
			return "DNS Query"
		}
	}

	if pkt.AppInfo != "" {
		return pkt.AppInfo
	}

	// Default TCP flags or payload length
	if pkt.Protocol == model.ProtocolTCP {
		return pkt.TCPFlags.String()
	}

	return fmt.Sprintf("Len=%d", len(pkt.Payload))
}

func (a *App) applyFilter(filter string) {
	a.mu.Lock()

	a.filter = filter
	a.filteredIdx = make([]int, 0)

	filterLower := strings.ToLower(filter)

	for i, pkt := range a.packets {
		if filterLower == "" {
			a.filteredIdx = append(a.filteredIdx, i)
			continue
		}

		// Simple string matching filter
		match := false

		// Check protocol
		if strings.Contains(strings.ToLower(pkt.Protocol.String()), filterLower) {
			match = true
		}

		// Check IP addresses
		if pkt.SrcIP != nil && strings.Contains(pkt.SrcIP.String(), filterLower) {
			match = true
		}
		if pkt.DstIP != nil && strings.Contains(pkt.DstIP.String(), filterLower) {
			match = true
		}

		// Check ports
		if strings.Contains(fmt.Sprintf("%d", pkt.SrcPort), filterLower) {
			match = true
		}
		if strings.Contains(fmt.Sprintf("%d", pkt.DstPort), filterLower) {
			match = true
		}

		if match {
			a.filteredIdx = append(a.filteredIdx, i)
		}
	}

	a.mu.Unlock()

	a.refreshPacketList()
}

func (a *App) toggleHexView() {
	a.showHex = !a.showHex
	if a.rightPanel == nil {
		return
	}

	if a.showHex {
		a.rightPanel.ResizeItem(a.hexView, 0, 1)
		a.updateStatus("Hex view enabled")
	} else {
		a.rightPanel.ResizeItem(a.hexView, 0, 0)
		a.updateStatus("Hex view hidden")
	}
}

func (a *App) focusNextPane() {
	panes := []tview.Primitive{a.packetList, a.detailTree}
	if a.showHex {
		panes = append(panes, a.hexView)
	}

	current := a.app.GetFocus()
	for i, pane := range panes {
		if current == pane {
			next := panes[(i+1)%len(panes)]
			a.app.SetFocus(next)
			return
		}
	}

	if len(panes) > 0 {
		a.app.SetFocus(panes[0])
	}
}

func (a *App) showFollowTCPStream() {
	a.mu.RLock()
	if a.selectedIdx < 0 || a.selectedIdx >= len(a.filteredIdx) {
		a.mu.RUnlock()
		a.updateStatus("No packet selected")
		return
	}

	packetIdx := a.filteredIdx[a.selectedIdx]
	if packetIdx < 0 || packetIdx >= len(a.packets) {
		a.mu.RUnlock()
		a.updateStatus("No packet selected")
		return
	}

	selected := a.packets[packetIdx]
	text, err := buildTCPStreamText(a.packets, selected)
	a.mu.RUnlock()
	if err != nil {
		a.updateStatus(err.Error())
		return
	}

	view := tview.NewTextView().
		SetScrollable(true).
		SetDynamicColors(true).
		SetText(text)
	view.SetBorder(true).SetTitle(" Follow TCP Stream (q/Esc to close) ")
	view.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			a.pages.RemovePage("follow")
			a.app.SetFocus(a.packetList)
			return nil
		}
		switch event.Rune() {
		case 'q':
			a.pages.RemovePage("follow")
			a.app.SetFocus(a.packetList)
			return nil
		}
		return event
	})

	update := a.queueUpdate
	if update == nil {
		update = func(fn func()) {
			a.app.QueueUpdateDraw(fn)
		}
	}
	update(func() {
		a.pages.AddPage("follow", view, true, true)
		a.app.SetFocus(view)
	})
}

func buildTCPStreamText(packets []*model.Packet, selected *model.Packet) (string, error) {
	if selected == nil {
		return "", fmt.Errorf("no packet selected")
	}
	if selected.Protocol != model.ProtocolTCP {
		return "", fmt.Errorf("selected packet is not TCP")
	}

	flowHash := selected.FlowHash()
	clientID := fmt.Sprintf("%s:%d", selected.SrcIP, selected.SrcPort)
	serverID := fmt.Sprintf("%s:%d", selected.DstIP, selected.DstPort)

	var clientBuf []byte
	var serverBuf []byte

	for _, pkt := range packets {
		if pkt == nil || pkt.Protocol != model.ProtocolTCP {
			continue
		}
		if pkt.FlowHash() != flowHash {
			continue
		}
		if len(pkt.Payload) == 0 {
			continue
		}
		if pkt.SrcIP.Equal(selected.SrcIP) && pkt.SrcPort == selected.SrcPort {
			clientBuf = append(clientBuf, pkt.Payload...)
		} else {
			serverBuf = append(serverBuf, pkt.Payload...)
		}
	}

	if len(clientBuf) == 0 && len(serverBuf) == 0 {
		return "", fmt.Errorf("no TCP payload data in stream")
	}

	clientText := formatStreamBytes(clientBuf)
	serverText := formatStreamBytes(serverBuf)

	return fmt.Sprintf("[yellow]Client (%s) -> Server (%s)[white]\n%s\n\n[yellow]Server -> Client[white]\n%s", clientID, serverID, clientText, serverText), nil
}

func formatStreamBytes(data []byte) string {
	if len(data) == 0 {
		return "<no data>"
	}

	var sb strings.Builder
	for _, b := range data {
		switch {
		case b == '\n' || b == '\r' || b == '\t':
			sb.WriteByte(b)
		case b >= 32 && b <= 126:
			sb.WriteByte(b)
		default:
			sb.WriteByte('.')
		}
	}

	return sb.String()
}

func (a *App) updateStatus(msg string) {
	a.statusBar.SetText(fmt.Sprintf(" %s | F1: Help | Ctrl+F: Filter | q: Quit", msg))
}

func (a *App) showHelp() {
	helpText := `[yellow]Wiretap TUI Help[white]

[green]Navigation:[white]
  j/Down    Move down
  k/Up      Move up
  g         Go to first packet
  G         Go to last packet

[green]Commands:[white]
  /         Open filter input
  Ctrl+F    Open filter input
	Tab       Cycle panes
	h         Toggle hex view
	f         Follow TCP stream
  F5        Refresh packet list
	F1/?      Show this help
  q         Quit
  Escape    Close dialog/Cancel

[green]Filter Examples:[white]
  tcp       Show TCP packets
  http      Show HTTP packets
  443       Show packets on port 443
  192.168   Show packets with matching IP

Press any key to close this help.`

	modal := tview.NewModal().
		SetText(helpText).
		AddButtons([]string{"Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			a.pages.RemovePage("help")
		})

	a.pages.AddPage("help", modal, true, true)
}

// LoadPcap loads packets from a pcap file.
func (a *App) LoadPcap(filename string) error {
	a.pcapFile = filename

	reader, err := capture.OpenPcap(filename)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer reader.Close()

	a.mu.Lock()
	a.packets = make([]*model.Packet, 0)

	iter := capture.NewPacketIterator(reader)
	for {
		pkt, ok := iter.Next()
		if !ok {
			break
		}
		a.packets = append(a.packets, pkt)
	}

	// Initialize filtered index
	a.filteredIdx = make([]int, len(a.packets))
	for i := range a.packets {
		a.filteredIdx[i] = i
	}
	a.mu.Unlock()

	a.refreshPacketList()
	return nil
}

// AddPacket adds a packet to the display (used during live capture).
func (a *App) AddPacket(pkt *model.Packet) {
	a.mu.Lock()
	idx := len(a.packets)
	a.packets = append(a.packets, pkt)

	// Check filter
	if a.matchesFilter(pkt) {
		a.filteredIdx = append(a.filteredIdx, idx)
	}
	a.mu.Unlock()

	// Update UI
	update := a.queueUpdate
	if update == nil {
		update = func(fn func()) {
			a.app.QueueUpdateDraw(fn)
		}
	}
	update(func() {
		a.refreshPacketList()
	})
}

func (a *App) matchesFilter(pkt *model.Packet) bool {
	if a.filter == "" {
		return true
	}

	filter := strings.ToLower(a.filter)

	if strings.Contains(strings.ToLower(pkt.Protocol.String()), filter) {
		return true
	}
	if pkt.SrcIP != nil && strings.Contains(pkt.SrcIP.String(), filter) {
		return true
	}
	if pkt.DstIP != nil && strings.Contains(pkt.DstIP.String(), filter) {
		return true
	}

	return false
}

// Run starts the TUI application.
func (a *App) Run() error {
	a.app.SetRoot(a.pages, true).EnableMouse(true)
	run := a.run
	if run == nil {
		run = a.app.Run
	}
	return run()
}

// Stop stops the TUI application.
func (a *App) Stop() {
	a.app.Stop()
}

func formatAddr(ip interface{}, port uint16) string {
	if ip == nil {
		return "?"
	}
	if port > 0 {
		return fmt.Sprintf("%v:%d", ip, port)
	}
	return fmt.Sprintf("%v", ip)
}
