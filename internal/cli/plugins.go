package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/wiretap/wiretap/internal/plugin"
	"github.com/wiretap/wiretap/internal/protocol"
)

func loadAndRegisterPlugins(registry *protocol.DissectorRegistry, pluginDir string, pluginFiles []string) (*plugin.Manager, error) {
	if registry == nil {
		return nil, nil
	}

	ctx := context.Background()
	hasPluginFiles := len(pluginFiles) > 0
	if !hasPluginFiles && pluginDir == "" {
		return nil, nil
	}

	if pluginDir != "" {
		if _, err := os.Stat(pluginDir); err != nil {
			if os.IsNotExist(err) && !hasPluginFiles {
				return nil, nil
			}
			if os.IsNotExist(err) {
				// Skip missing plugin directory when explicit plugin files are provided.
			} else {
				return nil, err
			}
		}
	}

	mgr := plugin.NewManager()

	if pluginDir != "" {
		if _, err := os.Stat(pluginDir); err == nil {
			if err := mgr.LoadPluginsFromDir(ctx, pluginDir); err != nil {
				return nil, err
			}
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
			return nil, err
		}
	}

	for _, p := range mgr.Plugins() {
		registry.Register(plugin.NewPluginDissector(p))
	}

	return mgr, nil
}
