package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/wiretap/wiretap/internal/plugin"
)

// Run starts the TUI with optional pcap file or live capture.
var runApp = func(app *App) error {
	return app.Run()
}

func Run(pcapFile, iface, filter, theme, pluginDir string, pluginFiles []string) error {
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

	// Load WASM plugins if provided
	if app.registry != nil && (pluginDir != "" || len(pluginFiles) > 0) {
		mgr := plugin.NewManager()
		ctx := context.Background()

		if pluginDir != "" {
			if err := mgr.LoadPluginsFromDir(ctx, pluginDir); err != nil {
				return fmt.Errorf("failed to load plugins: %w", err)
			}
		}

		for _, p := range pluginFiles {
			path := strings.TrimSpace(p)
			if path == "" {
				continue
			}
			if !filepath.IsAbs(path) && pluginDir != "" {
				path = filepath.Join(pluginDir, path)
			}
			if _, err := mgr.LoadPlugin(ctx, path); err != nil {
				return fmt.Errorf("failed to load plugin %s: %w", path, err)
			}
		}

		for _, p := range mgr.Plugins() {
			app.registry.Register(plugin.NewPluginDissector(p))
		}
		defer mgr.Close(ctx)
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
