package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wiretap/wiretap/internal/model"
)

func TestNewManager(t *testing.T) {
	mgr := NewManager()
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	if mgr.plugins == nil {
		t.Error("plugins map should be initialized")
	}
}

func TestManager_ListPlugins_Empty(t *testing.T) {
	mgr := NewManager()
	plugins := mgr.ListPlugins()
	if len(plugins) != 0 {
		t.Errorf("Expected empty plugin list, got %d", len(plugins))
	}
}

func TestManager_GetPlugin_NotFound(t *testing.T) {
	mgr := NewManager()
	_, err := mgr.GetPlugin("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent plugin")
	}
}

func TestManager_UnloadPlugin_NotFound(t *testing.T) {
	mgr := NewManager()
	err := mgr.UnloadPlugin(context.Background(), "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent plugin")
	}
}

func TestManager_LoadPlugin_FileNotFound(t *testing.T) {
	mgr := NewManager()
	_, err := mgr.LoadPlugin(context.Background(), "/nonexistent/plugin.wasm")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestManager_LoadPluginsFromDir_NotFound(t *testing.T) {
	mgr := NewManager()
	err := mgr.LoadPluginsFromDir(context.Background(), "/nonexistent/plugins")
	if err == nil {
		t.Error("Expected error for nonexistent directory")
	}
}

func TestManager_Close_Empty(t *testing.T) {
	mgr := NewManager()
	err := mgr.Close(context.Background())
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestPluginInfo(t *testing.T) {
	info := PluginInfo{
		Name:    "test-plugin",
		Version: "1.0.0",
		Path:    "/path/to/plugin.wasm",
	}

	if info.Name != "test-plugin" {
		t.Errorf("Name = %s, want test-plugin", info.Name)
	}
	if info.Version != "1.0.0" {
		t.Errorf("Version = %s, want 1.0.0", info.Version)
	}
}

func TestNewPluginDissector(t *testing.T) {
	plugin := &Plugin{
		info: PluginInfo{
			Name:    "test-dissector",
			Version: "1.0.0",
		},
	}

	dissector := NewPluginDissector(plugin)
	if dissector == nil {
		t.Fatal("NewPluginDissector returned nil")
	}
	if dissector.Name() != "test-dissector" {
		t.Errorf("Name() = %s, want test-dissector", dissector.Name())
	}
}

func TestPluginDissector_Detect_NoDetectFunction(t *testing.T) {
	plugin := &Plugin{
		info: PluginInfo{Name: "test"},
	}

	dissector := NewPluginDissector(plugin)
	result := dissector.Detect([]byte("test data"))
	if result {
		t.Error("Detect should return false when detect function is missing")
	}
}

func TestPlugin_Info(t *testing.T) {
	plugin := &Plugin{
		info: PluginInfo{
			Name:    "test",
			Version: "2.0.0",
			Path:    "/test.wasm",
		},
	}

	info := plugin.Info()
	if info.Name != "test" {
		t.Errorf("Info().Name = %s, want test", info.Name)
	}
	if info.Version != "2.0.0" {
		t.Errorf("Info().Version = %s, want 2.0.0", info.Version)
	}
}

func TestPlugin_Name(t *testing.T) {
	plugin := &Plugin{
		info: PluginInfo{Name: "my-plugin"},
	}

	if plugin.Name() != "my-plugin" {
		t.Errorf("Name() = %s, want my-plugin", plugin.Name())
	}
}

func TestPlugin_Detect_NoFunction(t *testing.T) {
	plugin := &Plugin{
		info: PluginInfo{Name: "test"},
	}

	_, err := plugin.Detect(context.Background(), []byte("test"))
	if err != ErrInvalidPluginAPI {
		t.Errorf("Expected ErrInvalidPluginAPI, got %v", err)
	}
}

func TestPlugin_Parse_NoFunction(t *testing.T) {
	plugin := &Plugin{
		info: PluginInfo{Name: "test"},
	}

	_, err := plugin.Parse(context.Background(), []byte("test"))
	if err != ErrInvalidPluginAPI {
		t.Errorf("Expected ErrInvalidPluginAPI, got %v", err)
	}
}

func TestPlugin_allocMemory_NoFunction(t *testing.T) {
	plugin := &Plugin{
		info: PluginInfo{Name: "test"},
	}

	_, err := plugin.allocMemory(context.Background(), 100)
	if err != ErrInvalidPluginAPI {
		t.Errorf("Expected ErrInvalidPluginAPI, got %v", err)
	}
}

func TestPlugin_freeMemory_NoFunction(t *testing.T) {
	plugin := &Plugin{
		info: PluginInfo{Name: "test"},
	}

	// Should not panic when freeFn is nil
	plugin.freeMemory(context.Background(), 0, 0)
}

func TestPlugin_Close_Empty(t *testing.T) {
	plugin := &Plugin{
		info: PluginInfo{Name: "test"},
	}

	err := plugin.Close(context.Background())
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestManager_LoadPluginFromBytes_InvalidWasm(t *testing.T) {
	mgr := NewManager()

	invalidWasm := []byte("this is not valid wasm")

	_, err := mgr.LoadPluginFromBytes(context.Background(), "invalid.wasm", invalidWasm)
	if err == nil {
		t.Error("Expected error for invalid WASM")
	}
}

func TestManager_LoadPluginsFromDir_EmptyDir(t *testing.T) {
	mgr := NewManager()

	// Create temporary empty directory
	tempDir, err := os.MkdirTemp("", "plugins-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	err = mgr.LoadPluginsFromDir(context.Background(), tempDir)
	if err != nil {
		t.Errorf("LoadPluginsFromDir() error = %v", err)
	}

	plugins := mgr.ListPlugins()
	if len(plugins) != 0 {
		t.Errorf("Expected 0 plugins, got %d", len(plugins))
	}
}

func TestManager_LoadPluginsFromDir_NonWasmFiles(t *testing.T) {
	mgr := NewManager()

	// Create temporary directory with non-wasm files
	tempDir, err := os.MkdirTemp("", "plugins-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create some non-wasm files
	os.WriteFile(filepath.Join(tempDir, "readme.txt"), []byte("readme"), 0644)
	os.WriteFile(filepath.Join(tempDir, "config.json"), []byte("{}"), 0644)

	err = mgr.LoadPluginsFromDir(context.Background(), tempDir)
	if err != nil {
		t.Errorf("LoadPluginsFromDir() error = %v", err)
	}

	plugins := mgr.ListPlugins()
	if len(plugins) != 0 {
		t.Errorf("Expected 0 plugins, got %d", len(plugins))
	}
}

func TestManager_LoadPluginsFromDir_WithSubdirectory(t *testing.T) {
	mgr := NewManager()

	// Create temporary directory with subdirectory
	tempDir, err := os.MkdirTemp("", "plugins-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a subdirectory (should be skipped)
	os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)

	err = mgr.LoadPluginsFromDir(context.Background(), tempDir)
	if err != nil {
		t.Errorf("LoadPluginsFromDir() error = %v", err)
	}

	plugins := mgr.ListPlugins()
	if len(plugins) != 0 {
		t.Errorf("Expected 0 plugins, got %d", len(plugins))
	}
}

func TestPluginDissector_Parse_NoParseFunction(t *testing.T) {
	plugin := &Plugin{
		info: PluginInfo{Name: "test-dissector"},
	}

	dissector := NewPluginDissector(plugin)
	pkt := &model.Packet{}
	err := dissector.Parse([]byte("test data"), pkt)
	if err == nil {
		t.Error("Expected error when parse function is missing")
	}
}

func TestPluginErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"PluginNotFound", ErrPluginNotFound, "plugin not found"},
		{"PluginLoadFailed", ErrPluginLoadFailed, "plugin load failed"},
		{"PluginCallFailed", ErrPluginCallFailed, "plugin call failed"},
		{"InvalidPluginAPI", ErrInvalidPluginAPI, "plugin does not implement required API"},
		{"PluginAlreadyExists", ErrPluginAlreadyExists, "plugin already loaded"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.want {
				t.Errorf("Error() = %v, want %v", tt.err.Error(), tt.want)
			}
		})
	}
}

// Minimal valid WASM module (empty module with no exports)
// This is the smallest valid WASM module: magic number + version
var minimalWasm = []byte{
	0x00, 0x61, 0x73, 0x6d, // magic: \0asm
	0x01, 0x00, 0x00, 0x00, // version: 1
}

func TestManager_LoadPluginFromBytes_MinimalWasm(t *testing.T) {
	mgr := NewManager()

	// Even a valid minimal WASM should fail because it lacks required functions
	_, err := mgr.LoadPluginFromBytes(context.Background(), "minimal.wasm", minimalWasm)
	if err == nil {
		t.Error("Expected error for WASM without required exports")
	}
}

func TestPluginDissector_Name(t *testing.T) {
	plugin := &Plugin{
		info: PluginInfo{
			Name:    "custom-protocol",
			Version: "1.0.0",
		},
	}

	dissector := NewPluginDissector(plugin)

	if dissector.Name() != "custom-protocol" {
		t.Errorf("Name() = %s, want custom-protocol", dissector.Name())
	}
}
