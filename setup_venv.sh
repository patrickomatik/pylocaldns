#!/bin/bash
# Setup a virtual environment and install dependencies

echo "Setting up a virtual environment for PyLocalDNS..."

# Check if python3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 not found. Please install Python 3 first."
    exit 1
fi

# Create a virtual environment
echo "Creating a virtual environment..."
python3 -m venv .venv
if [ $? -ne 0 ]; then
    echo "Error: Failed to create virtual environment. Make sure venv module is available."
    exit 1
fi

# Activate the virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate
if [ $? -ne 0 ]; then
    echo "Error: Failed to activate virtual environment."
    exit 1
fi

# Install dependencies
echo "Installing dependencies in the virtual environment..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    pip install flask>=2.0.0
fi

if [ $? -eq 0 ]; then
    echo "Installation completed successfully."
    echo "To activate the virtual environment in the future, run:"
    echo "source .venv/bin/activate"
    echo ""
    echo "You can now run PyLocalDNS with Flask web UI using:"
    echo "./run_flask_server.sh"
else
    echo "Installation failed. Please check for errors above."
    exit 1
fi

# Deactivate the virtual environment
deactivate
