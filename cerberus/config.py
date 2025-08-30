#!/usr/bin/env python3
"""
Cerberus Configuration File
"""

# Default credentials and connection settings
DEFAULT_DOMAIN = "lab.local"
DEFAULT_DC_IP = "192.168.1.10"
DEFAULT_USER = "lowpriv_user"
DEFAULT_PASSWORD = "Password123!"

# Tool behavior settings
REQUEST_DELAY = (1, 3)  # Random delay between requests in seconds
LDAP_PAGE_SIZE = 1000   # LDAP query page size
OUTPUT_DIR = "results"  # Directory for output files

# Wordlist for password cracking
WORDLIST_PATH = "wordlists/common_passwords.txt"

# Kerberos settings
KERBEROS_TIMEOUT = 30  # seconds

# Color settings for output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'