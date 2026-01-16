// Package plugin provides a WebAssembly-based plugin system for wiretap.
// Plugins can implement custom protocol dissectors that run in a sandboxed
// WASM runtime for security and portability.
package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/wiretap/wiretap/internal/model"
)

// Common plugin errors.
var (
	ErrPluginNotFound      = errors.New("plugin not found")
	ErrPluginLoadFailed    = errors.New("plugin load failed")
	ErrPluginCallFailed    = errors.New("plugin call failed")
	ErrInvalidPluginAPI    = errors.New("plugin does not implement required API")
	ErrPluginAlreadyExists = errors.New("plugin already loaded")
)

// PluginAPI defines the functions a WASM plugin must export.
// These are called by the host to interact with the plugin.
const (
	// Plugin metadata functions.
	fnPluginName    = "plugin_name"
	fnPluginVersion = "plugin_version"

	// Dissector functions.
	fnDetect = "detect"
	fnParse  = "parse"

	// Memory allocation (plugin-side).
	fnAlloc = "alloc"
	fnFree  = "free"
)

// PluginInfo contains metadata about a loaded plugin.
type PluginInfo struct {
	Name    string
	Version string
	Path    string
}

// Plugin represents a loaded WASM plugin.
type Plugin struct {
	mu      sync.RWMutex
	info    PluginInfo
	runtime wazero.Runtime
	module  api.Module

	// Exported functions.
	detectFn api.Function
	parseFn  api.Function
	allocFn  api.Function
	freeFn   api.Function
}

// Info returns the plugin metadata.
func (p *Plugin) Info() PluginInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.info
}

// Name returns the plugin name.
func (p *Plugin) Name() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.info.Name
}

// Detect checks if the plugin can handle the given data.
// Returns true if the plugin can parse this data.
func (p *Plugin) Detect(ctx context.Context, data []byte) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.detectFn == nil {
		return false, ErrInvalidPluginAPI
	}

	// Allocate memory in plugin for the data.
	ptr, err := p.allocMemory(ctx, uint32(len(data)))
	if err != nil {
		return false, fmt.Errorf("alloc memory: %w", err)
	}
	defer p.freeMemory(ctx, ptr, uint32(len(data)))

	// Write data to plugin memory.
	if !p.module.Memory().Write(ptr, data) {
		return false, errors.New("failed to write to plugin memory")
	}

	// Call detect function.
	results, err := p.detectFn.Call(ctx, uint64(ptr), uint64(len(data)))
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrPluginCallFailed, err)
	}

	return results[0] != 0, nil
}

// Parse parses the data and returns parsed information.
// The result is a JSON-encoded map of parsed fields.
func (p *Plugin) Parse(ctx context.Context, data []byte) (map[string]interface{}, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.parseFn == nil {
		return nil, ErrInvalidPluginAPI
	}

	// Allocate memory for input data.
	inputPtr, err := p.allocMemory(ctx, uint32(len(data)))
	if err != nil {
		return nil, fmt.Errorf("alloc input memory: %w", err)
	}
	defer p.freeMemory(ctx, inputPtr, uint32(len(data)))

	// Write input data.
	if !p.module.Memory().Write(inputPtr, data) {
		return nil, errors.New("failed to write input to plugin memory")
	}

	// Allocate memory for output length (4 bytes for uint32).
	outLenPtr, err := p.allocMemory(ctx, 4)
	if err != nil {
		return nil, fmt.Errorf("alloc output length memory: %w", err)
	}
	defer p.freeMemory(ctx, outLenPtr, 4)

	// Call parse function.
	// Returns: pointer to JSON output (0 on error).
	results, err := p.parseFn.Call(ctx, uint64(inputPtr), uint64(len(data)), uint64(outLenPtr))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPluginCallFailed, err)
	}

	outputPtr := uint32(results[0])
	if outputPtr == 0 {
		return nil, nil // No data parsed.
	}

	// Read output length.
	outLenBytes, ok := p.module.Memory().Read(outLenPtr, 4)
	if !ok {
		return nil, errors.New("failed to read output length")
	}
	outLen := uint32(outLenBytes[0]) |
		uint32(outLenBytes[1])<<8 |
		uint32(outLenBytes[2])<<16 |
		uint32(outLenBytes[3])<<24

	// Read output JSON.
	outputBytes, ok := p.module.Memory().Read(outputPtr, outLen)
	if !ok {
		return nil, errors.New("failed to read output from plugin memory")
	}
	defer p.freeMemory(ctx, outputPtr, outLen)

	// Parse JSON output.
	var result map[string]interface{}
	if err := json.Unmarshal(outputBytes, &result); err != nil {
		return nil, fmt.Errorf("parse plugin output: %w", err)
	}

	return result, nil
}

// allocMemory allocates memory in the plugin.
func (p *Plugin) allocMemory(ctx context.Context, size uint32) (uint32, error) {
	if p.allocFn == nil {
		return 0, ErrInvalidPluginAPI
	}

	results, err := p.allocFn.Call(ctx, uint64(size))
	if err != nil {
		return 0, err
	}

	ptr := uint32(results[0])
	if ptr == 0 {
		return 0, errors.New("plugin alloc returned null")
	}

	return ptr, nil
}

// freeMemory frees memory in the plugin.
func (p *Plugin) freeMemory(ctx context.Context, ptr, size uint32) {
	if p.freeFn != nil {
		p.freeFn.Call(ctx, uint64(ptr), uint64(size))
	}
}

// Close releases plugin resources.
func (p *Plugin) Close(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error

	if p.module != nil {
		if err := p.module.Close(ctx); err != nil {
			errs = append(errs, err)
		}
		p.module = nil
	}

	if p.runtime != nil {
		if err := p.runtime.Close(ctx); err != nil {
			errs = append(errs, err)
		}
		p.runtime = nil
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// Manager manages loaded plugins.
type Manager struct {
	mu      sync.RWMutex
	plugins map[string]*Plugin
}

// NewManager creates a new plugin manager.
func NewManager() *Manager {
	return &Manager{
		plugins: make(map[string]*Plugin),
	}
}

// LoadPlugin loads a WASM plugin from file.
func (m *Manager) LoadPlugin(ctx context.Context, path string) (*Plugin, error) {
	// Read WASM file.
	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPluginLoadFailed, err)
	}

	return m.LoadPluginFromBytes(ctx, path, wasmBytes)
}

// LoadPluginFromBytes loads a WASM plugin from bytes.
func (m *Manager) LoadPluginFromBytes(ctx context.Context, name string, wasmBytes []byte) (*Plugin, error) {
	// Create runtime.
	runtime := wazero.NewRuntime(ctx)

	// Instantiate WASI for basic I/O.
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		runtime.Close(ctx)
		return nil, fmt.Errorf("instantiate WASI: %w", err)
	}

	// Compile and instantiate module.
	module, err := runtime.Instantiate(ctx, wasmBytes)
	if err != nil {
		runtime.Close(ctx)
		return nil, fmt.Errorf("%w: %v", ErrPluginLoadFailed, err)
	}

	// Get exported functions.
	plugin := &Plugin{
		info: PluginInfo{
			Path: name,
		},
		runtime:  runtime,
		module:   module,
		detectFn: module.ExportedFunction(fnDetect),
		parseFn:  module.ExportedFunction(fnParse),
		allocFn:  module.ExportedFunction(fnAlloc),
		freeFn:   module.ExportedFunction(fnFree),
	}

	// Verify required functions exist.
	if plugin.detectFn == nil || plugin.parseFn == nil {
		plugin.Close(ctx)
		return nil, fmt.Errorf("%w: missing detect or parse function", ErrInvalidPluginAPI)
	}

	// Get plugin metadata.
	if nameFn := module.ExportedFunction(fnPluginName); nameFn != nil {
		if nameResult, err := nameFn.Call(ctx); err == nil && len(nameResult) == 2 {
			ptr, length := uint32(nameResult[0]), uint32(nameResult[1])
			if nameBytes, ok := module.Memory().Read(ptr, length); ok {
				plugin.info.Name = string(nameBytes)
			}
		}
	}
	if plugin.info.Name == "" {
		plugin.info.Name = filepath.Base(name)
	}

	if versionFn := module.ExportedFunction(fnPluginVersion); versionFn != nil {
		if versionResult, err := versionFn.Call(ctx); err == nil && len(versionResult) == 2 {
			ptr, length := uint32(versionResult[0]), uint32(versionResult[1])
			if versionBytes, ok := module.Memory().Read(ptr, length); ok {
				plugin.info.Version = string(versionBytes)
			}
		}
	}

	// Check for duplicate.
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.plugins[plugin.info.Name]; exists {
		plugin.Close(ctx)
		return nil, fmt.Errorf("%w: %s", ErrPluginAlreadyExists, plugin.info.Name)
	}

	m.plugins[plugin.info.Name] = plugin

	return plugin, nil
}

// LoadPluginsFromDir loads all WASM plugins from a directory.
func (m *Manager) LoadPluginsFromDir(ctx context.Context, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read plugin directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) != ".wasm" {
			continue
		}

		path := filepath.Join(dir, name)
		if _, err := m.LoadPlugin(ctx, path); err != nil {
			// Log warning but continue loading other plugins.
			fmt.Fprintf(os.Stderr, "Warning: failed to load plugin %s: %v\n", path, err)
		}
	}

	return nil
}

// GetPlugin returns a plugin by name.
func (m *Manager) GetPlugin(name string) (*Plugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.plugins[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPluginNotFound, name)
	}

	return plugin, nil
}

// ListPlugins returns all loaded plugins.
func (m *Manager) ListPlugins() []PluginInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]PluginInfo, 0, len(m.plugins))
	for _, p := range m.plugins {
		infos = append(infos, p.Info())
	}

	return infos
}

// UnloadPlugin unloads a plugin by name.
func (m *Manager) UnloadPlugin(ctx context.Context, name string) error {
	m.mu.Lock()
	plugin, ok := m.plugins[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrPluginNotFound, name)
	}
	delete(m.plugins, name)
	m.mu.Unlock()

	return plugin.Close(ctx)
}

// Close unloads all plugins and releases resources.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	plugins := make([]*Plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		plugins = append(plugins, p)
	}
	m.plugins = make(map[string]*Plugin)
	m.mu.Unlock()

	var errs []error
	for _, p := range plugins {
		if err := p.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// PluginDissector wraps a plugin as a protocol dissector.
type PluginDissector struct {
	plugin *Plugin
}

// NewPluginDissector creates a dissector from a plugin.
func NewPluginDissector(plugin *Plugin) *PluginDissector {
	return &PluginDissector{plugin: plugin}
}

// Name returns the dissector name.
func (d *PluginDissector) Name() string {
	return d.plugin.Name()
}

// Detect checks if this dissector can handle the data.
func (d *PluginDissector) Detect(data []byte) bool {
	ctx := context.Background()
	result, err := d.plugin.Detect(ctx, data)
	if err != nil {
		return false
	}
	return result
}

// Parse parses the data and populates the packet.
func (d *PluginDissector) Parse(data []byte, pkt *model.Packet) error {
	ctx := context.Background()
	result, err := d.plugin.Parse(ctx, data)
	if err != nil {
		return err
	}

	// Populate packet from parsed fields.
	pkt.ApplicationProtocol = d.plugin.Name()

	if appInfo, ok := result["app_info"].(string); ok {
		pkt.AppInfo = appInfo
	}

	// Store plugin result in packet for display.
	if pkt.Extra == nil {
		pkt.Extra = make(map[string]interface{})
	}
	pkt.Extra["plugin_"+d.plugin.Name()] = result

	return nil
}
