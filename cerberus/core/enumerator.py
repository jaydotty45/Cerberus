#!/usr/bin/env python3
"""
Active Directory enumeration module for Cerberus
"""

import json
from ldap3 import SUBTREE
from core.utils import print_status, print_success, print_warning, random_delay, write_to_file

class ADEnumerator:
    def __init__(self, ldap_connection, domain):
        self.ldap_conn = ldap_connection
        self.domain = domain
        self.domain_dn = ",".join([f"DC={part}" for part in domain.split(".")])
        self.users = []
        self.computers = []
        self.groups = []
        self.vulnerabilities = []
        
    def enumerate_domain(self):
        """Perform comprehensive AD enumeration"""
        print_status("Starting Active Directory enumeration")
        
        # Enumerate users
        self.enumerate_users()
        
        # Enumerate computers
        self.enumerate_computers()
        
        # Enumerate groups
        self.enumerate_groups()
        
        # Check for vulnerabilities
        self.check_kerberoastable()
        self.check_asreproastable()
        
        print_success("Active Directory enumeration completed")
        return self.vulnerabilities
        
    def enumerate_users(self):
        """Enumerate all domain users"""
        print_status("Enumerating domain users")
        
        search_filter = "(objectClass=user)"
        attributes = [
            "sAMAccountName", "userPrincipalName", "memberOf", 
            "servicePrincipalName", "userAccountControl", "description",
            "lastLogon", "pwdLastSet", "whenCreated"
        ]
        
        self.ldap_conn.search(
            search_base=self.domain_dn,
            search_filter=search_filter,
            attributes=attributes,
            search_scope=SUBTREE,
            paged_size=1000
        )
        
        for entry in self.ldap_conn.entries:
            user_data = json.loads(entry.entry_to_json())['attributes']
            self.users.append(user_data)
            
        print_success(f"Found {len(self.users)} users")
        
    def enumerate_computers(self):
        """Enumerate all domain computers"""
        print_status("Enumerating domain computers")
        
        search_filter = "(objectClass=computer)"
        attributes = [
            "sAMAccountName", "operatingSystem", "operatingSystemVersion",
            "lastLogon", "whenCreated", "dNSHostName"
        ]
        
        self.ldap_conn.search(
            search_base=self.domain_dn,
            search_filter=search_filter,
            attributes=attributes,
            search_scope=SUBTREE,
            paged_size=1000
        )
        
        for entry in self.ldap_conn.entries:
            computer_data = json.loads(entry.entry_to_json())['attributes']
            self.computers.append(computer_data)
            
        print_success(f"Found {len(self.computers)} computers")
        
    def enumerate_groups(self):
        """Enumerate all domain groups"""
        print_status("Enumerating domain groups")
        
        search_filter = "(objectClass=group)"
        attributes = [
            "sAMAccountName", "member", "memberOf", "description"
        ]
        
        self.ldap_conn.search(
            search_base=self.domain_dn,
            search_filter=search_filter,
            attributes=attributes,
            search_scope=SUBTREE,
            paged_size=1000
        )
        
        for entry in self.ldap_conn.entries:
            group_data = json.loads(entry.entry_to_json())['attributes']
            self.groups.append(group_data)
            
        print_success(f"Found {len(self.groups)} groups")
        
    def check_kerberoastable(self):
        """Find users with SPNs (Kerberoastable)"""
        print_status("Checking for Kerberoastable accounts (users with SPNs)")
        
        for user in self.users:
            if 'servicePrincipalName' in user and user['servicePrincipalName']:
                vulnerability = {
                    'type': 'KERBEROASTING',
                    'target': user['sAMAccountName'],
                    'details': {
                        'spns': user['servicePrincipalName'],
                        'user_account_control': user.get('userAccountControl', [0])[0]
                    }
                }
                self.vulnerabilities.append(vulnerability)
                print_warning(f"Kerberoastable user found: {user['sAMAccountName']}")
                
        print_success(f"Found {len([v for v in self.vulnerabilities if v['type'] == 'KERBEROASTING'])} Kerberoastable accounts")
        
    def check_asreproastable(self):
        """Find users with DONT_REQ_PREAUTH flag (AS-REP roastable)"""
        print_status("Checking for AS-REP roastable accounts")
        
        # UserAccountControl value for DONT_REQ_PREAUTH
        DONT_REQ_PREAUTH = 0x400000
        
        for user in self.users:
            uac = user.get('userAccountControl', [0])[0]
            if uac & DONT_REQ_PREAUTH:
                vulnerability = {
                    'type': 'ASREP',
                    'target': user['sAMAccountName'],
                    'details': {
                        'user_account_control': uac
                    }
                }
                self.vulnerabilities.append(vulnerability)
                print_warning(f"AS-REP roastable user found: {user['sAMAccountName']}")
                
        print_success(f"Found {len([v for v in self.vulnerabilities if v['type'] == 'ASREP'])} AS-REP roastable accounts")
        
    def export_findings(self):
        """Export enumeration findings to files"""
        print_status("Exporting findings to files")
        
        # Export users
        users_file = write_to_file("users.json", json.dumps(self.users, indent=2))
        
        # Export computers
        computers_file = write_to_file("computers.json", json.dumps(self.computers, indent=2))
        
        # Export groups
        groups_file = write_to_file("groups.json", json.dumps(self.groups, indent=2))
        
        # Export vulnerabilities
        vulns_file = write_to_file("vulnerabilities.json", json.dumps(self.vulnerabilities, indent=2))
        
        print_success(f"Findings exported to: {users_file}, {computers_file}, {groups_file}, {vulns_file}")