# Flask Requirement for PyLocalDNS

## Overview

PyLocalDNS uses Flask for its web user interface. Flask is a lightweight WSGI web application framework in Python that provides a solid foundation for web applications while maintaining simplicity and flexibility.

## Installation

To use PyLocalDNS, you must have Flask installed. You can install Flask using one of the following methods:

### Using the install script

```bash
./install_flask.sh
```

This script will automatically install Flask and any other required dependencies.

### Using pip directly

```bash
pip install flask>=2.0.0
```

Or if you're using Python 3 explicitly:

```bash
pip3 install flask>=2.0.0
```

### Using requirements.txt

```bash
pip install -r requirements.txt
```

## Why Flask?

Flask was chosen for PyLocalDNS for several reasons:

1. **Lightweight**: Flask is minimalist while still providing all the features needed for a web UI.
2. **Ease of use**: Flask's simplicity makes it easy to understand and maintain.
3. **Flexibility**: Flask doesn't enforce any particular project structure, allowing for adaptability.
4. **Template engine**: Flask uses Jinja2 templates, which make it easy to create dynamic HTML pages.
5. **Security**: Flask provides built-in security features to help protect against common web vulnerabilities.

## Troubleshooting

If you encounter any issues with the Flask installation:

1. Make sure you have Python 3.6 or newer installed
2. Check that pip is installed and up to date
3. Try installing Flask with the `--user` flag if you don't have admin privileges
4. If you're using a virtual environment, ensure it's activated before installing

## Application Structure

The Flask application in PyLocalDNS is organized as follows:

- `app.py`: The main Flask application
- `flask_routes.py`: Route handlers for all web UI endpoints
- `templates/`: HTML templates used by Flask
- `static/`: Static files like CSS, JavaScript, and images

## Port Configuration

By default, the Flask web UI runs on port 8080. You can change this port using the `--webui-port` command-line option when starting PyLocalDNS.
