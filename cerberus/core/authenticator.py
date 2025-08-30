#!/usr/bin/env python3
"""
Authentication handler for Cerberus
"""

import sys
from impacket.smbconnection import SMBConnection
from impacket.ldap import ldapasn1
from ldap3 import Server, Connection, ALL, NTLM, Tls
from core.utils import print_status, print_error, print_success, random_delay

class Authenticator:
    def __init__(self, domain, username, password, lmhash="", nthash="", dc_ip=None):
        self.domain = domain
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.dc_ip = dc_ip or domain
        self.smb_conn = None
        self.ldap_conn = None
        
    def smb_authenticate(self):
        """Authenticate via SMB"""
        try:
            print_status(f"Attempting SMB authentication to {self.dc_ip}")
            self.smb_conn = SMBConnection(self.dc_ip, self.dc_ip)
            
            if self.lmhash and self.nthash:
                self.smb_conn.login(self.username, '', self.domain, self.lmhash, self.nthash)
            else:
                self.smb_conn.login(self.username, self.password, self.domain)
                
            print_success(f"SMB authentication successful as {self.domain}\\{self.username}")
            return True
            
        except Exception as e:
            print_error(f"SMB authentication failed: {str(e)}")
            return False
    
    def ldap_authenticate(self):
        """Authenticate via LDAP"""
        try:
            print_status(f"Attempting LDAP authentication to {self.dc_ip}")
            server = Server(self.dc_ip, get_info=ALL)
            
            if self.lmhash and self.nthash:
                # NTLM authentication
                self.ldap_conn = Connection(
                    server, 
                    user=f"{self.domain}\\{self.username}", 
                    password=self.lmhash + ":" + self.nthash,
                    authentication=NTLM
                )
            else:
                # Password authentication
                self.ldap_conn = Connection(
                    server, 
                    user=f"{self.domain}\\{self.username}", 
                    password=self.password,
                    authentication=NTLM
                )
            
            if not self.ldap_conn.bind():
                print_error(f"LDAP bind failed: {self.ldap_conn.result}")
                return False
                
            print_success(f"LDAP authentication successful as {self.domain}\\{self.username}")
            return True
            
        except Exception as e:
            print_error(f"LDAP authentication failed: {str(e)}")
            return False
    
    def get_ldap_connection(self):
        """Get the LDAP connection"""
        return self.ldap_conn
    
    def get_smb_connection(self):
        """Get the SMB connection"""
        return self.smb_conn