#!/usr/bin/env python3
"""
Password cracking module for Cerberus
"""

import os
import subprocess
import tempfile
from core.utils import print_status, print_success, print_error
from config import WORDLIST_PATH

class CrackEngine:
    def __init__(self, wordlist_path=WORDLIST_PATH):
        self.wordlist_path = wordlist_path
        
    def crack_hash(self, hash_string, hash_type="kerberos"):
        """Attempt to crack a hash using John the Ripper or Hashcat"""
        print_status(f"Attempting to crack {hash_type} hash")
        
        # Create a temporary file with the hash
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hash') as f:
            f.write(hash_string + '\n')
            hash_file = f.name
        
        try:
            # Try John the Ripper first
            if self._check_john():
                result = self._crack_with_john(hash_file, hash_type)
                if result:
                    os.unlink(hash_file)
                    return result
            
            # Fall back to Hashcat
            if self._check_hashcat():
                result = self._crack_with_hashcat(hash_file, hash_type)
                if result:
                    os.unlink(hash_file)
                    return result
                    
            print_error("No cracking tools available or password not found in wordlist")
            return None
            
        except Exception as e:
            print_error(f"Cracking failed: {str(e)}")
            return None
        finally:
            # Clean up
            if os.path.exists(hash_file):
                os.unlink(hash_file)
    
    def _check_john(self):
        """Check if John the Ripper is available"""
        try:
            subprocess.run(["john", "--help"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _check_hashcat(self):
        """Check if Hashcat is available"""
        try:
            subprocess.run(["hashcat", "--help"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _crack_with_john(self, hash_file, hash_type):
        """Crack hash using John the Ripper"""
        try:
            # Map hash type to John format
            john_format = {
                "kerberos": "krb5tgs" if "tgs" in hash_file else "krb5asrep"
            }.get(hash_type, "krb5tgs")
            
            # Run John
            cmd = ["john", "--format=" + john_format, "--wordlist=" + self.wordlist_path, hash_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Show cracked passwords
                cmd = ["john", "--show", hash_file]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if "password hash cracked" in result.stdout or "0 password hashes cracked" not in result.stdout:
                    # Parse the cracked password
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line and ":" in line:
                            parts = line.split(":")
                            if len(parts) >= 2:
                                return parts[1]  # Return the cracked password
            return None
            
        except Exception as e:
            print_error(f"John cracking failed: {str(e)}")
            return None
    
    def _crack_with_hashcat(self, hash_file, hash_type):
        """Crack hash using Hashcat"""
        try:
            # Map hash type to Hashcat mode
            hashcat_mode = {
                "kerberos": 13100 if "tgs" in hash_file else 18200
            }.get(hash_type, 13100)
            
            # Run Hashcat
            cmd = [
                "hashcat", 
                "-m", str(hashcat_mode), 
                "-a", "0", 
                hash_file, 
                self.wordlist_path,
                "--potfile-disable"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Check if any passwords were cracked
                cmd = ["hashcat", "-m", str(hashcat_mode), "--show", hash_file]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.stdout and ":" in result.stdout:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line and ":" in line:
                            parts = line.split(":")
                            if len(parts) >= 2:
                                return parts[1]  # Return the cracked password
            return None
            
        except Exception as e:
            print_error(f"Hashcat cracking failed: {str(e)}")
            return None