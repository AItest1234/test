#!/bin/bash
# Setup script for WinSCP Extension

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║           WinSCP Extension - Installation Script             ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
required_version="3.8"

if (( $(echo "$python_version < $required_version" | bc -l) )); then
    echo "❌ Error: Python 3.8 or higher is required (found $python_version)"
    exit 1
fi
echo "✓ Python $python_version found"

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "❌ Error: pip3 is not installed"
    echo "Please install pip3 first: sudo apt install python3-pip"
    exit 1
fi
echo "✓ pip3 found"

# Install dependencies
echo ""
echo "Installing dependencies..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

echo ""
echo "✓ Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Run 'python3 main.py info' to see system information"
echo "  2. Run 'python3 main.py setup' to start the setup wizard"
echo "  3. See QUICKSTART.md for usage examples"
echo ""
echo "For help: python3 main.py --help"
echo ""
