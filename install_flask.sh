#!/bin/bash
# Install Flask and required dependencies for PyLocalDNS

echo "Installing Flask and required dependencies..."

# Check if pip is available
if ! command -v pip &> /dev/null; then
    if command -v pip3 &> /dev/null; then
        PIP_CMD="pip3"
    else
        echo "Error: pip or pip3 not found. Please install Python and pip first."
        exit 1
    fi
else
    PIP_CMD="pip"
fi

# Install from requirements file if it exists
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies from requirements.txt..."
    $PIP_CMD install --user -r requirements.txt
else
    # Otherwise, install Flask directly
    echo "Installing Flask directly..."
    $PIP_CMD install --user flask>=2.0.0
fi

# Check if installation was successful
if [ $? -eq 0 ]; then
    echo "Installation completed successfully."
    echo "You can now run PyLocalDNS with Flask web UI using:"
    echo "./run_flask_server.sh"
else
    echo "Installation failed. Please check for errors above."
    exit 1
fi
