package tui

import (
	"fmt"
)

// Run starts the TUI with optional pcap file or live capture.
var runApp = func(app *App) error {
	return app.Run()
}

func Run(pcapFile, iface, filter, theme string) error {
	app := New()

	// Apply theme
	applyTheme(theme)

	// Load pcap file if specified
	if pcapFile != "" {
		if err := app.LoadPcap(pcapFile); err != nil {
			return fmt.Errorf("failed to load pcap: %w", err)
		}
	}

	// Apply initial filter
	if filter != "" {
		app.applyFilter(filter)
	}

	// TODO: Start live capture if interface specified
	// if iface != "" {
	//     go app.startCapture(iface)
	// }

	return runApp(app)
}

func applyTheme(theme string) {
	// Theme configuration can be expanded later
	// For now, we use the default tview theme
	switch theme {
	case "dark":
		// Dark theme is the default
	case "light":
		// Light theme adjustments
	default:
		// Default theme
	}
}
