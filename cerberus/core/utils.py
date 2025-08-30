#!/usr/bin/env python3
"""
Utility functions for Cerberus
"""

import random
import time
import os
import sys
from colorama import init, Fore, Style
from config import Colors

# Initialize colorama
init()

def print_status(message):
    """Print status message"""
    print(f"{Colors.BLUE}[*]{Colors.END} {message}")

def print_success(message):
    """Print success message"""
    print(f"{Colors.GREEN}[+]{Colors.END} {message}")

def print_warning(message):
    """Print warning message"""
    print(f"{Colors.YELLOW}[!]{Colors.END} {message}")

def print_error(message):
    """Print error message"""
    print(f"{Colors.RED}[-]{Colors.END} {message}")

def print_critical(message):
    """Print critical error message and exit"""
    print(f"{Colors.RED}[CRITICAL]{Colors.END} {message}")
    sys.exit(1)

def random_delay():
    """Add a random delay between requests"""
    delay = random.uniform(config.REQUEST_DELAY[0], config.REQUEST_DELAY[1])
    time.sleep(delay)

def ensure_output_dir():
    """Ensure the output directory exists"""
    if not os.path.exists(config.OUTPUT_DIR):
        os.makedirs(config.OUTPUT_DIR)

def write_to_file(filename, content):
    """Write content to a file in the output directory"""
    ensure_output_dir()
    filepath = os.path.join(config.OUTPUT_DIR, filename)
    with open(filepath, 'w') as f:
        f.write(content)
    return filepath