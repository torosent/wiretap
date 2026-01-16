#!/bin/bash
# Build all WASM plugins
# Requires: rustup target add wasm32-wasip1

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR"

echo "Building Wiretap WASM plugins..."

# Check for Rust WASM target
if ! rustup target list --installed | grep -q wasm32-wasip1; then
    echo "Installing wasm32-wasip1 target..."
    rustup target add wasm32-wasip1
fi

# Build each plugin
for plugin_dir in "$SCRIPT_DIR/examples"/*/; do
    if [ -f "$plugin_dir/Cargo.toml" ]; then
        plugin_name=$(basename "$plugin_dir")
        echo "Building $plugin_name..."
        
        (cd "$plugin_dir" && cargo build --release --target wasm32-wasip1)
        
        # Copy the built WASM file
        wasm_file="$plugin_dir/target/wasm32-wasip1/release/${plugin_name//-/_}.wasm"
        if [ -f "$wasm_file" ]; then
            cp "$wasm_file" "$OUTPUT_DIR/${plugin_name}.wasm"
            echo "  -> ${plugin_name}.wasm"
        fi
    fi
done

echo ""
echo "Built plugins:"
ls -la "$OUTPUT_DIR"/*.wasm 2>/dev/null || echo "No .wasm files found"
