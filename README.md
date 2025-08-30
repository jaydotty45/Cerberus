# Cerberus 🐍

> *"The three-headed hound that guards the gates of AD Hell."*

Cerberus is an automated post-exploitation tool that demonstrates how attackers can chain common Active Directory misconfigurations to escalate from a low-privileged user to Domain Administrator.

**⚠️ LEGAL DISCLAIMER: This tool is for educational purposes and authorized penetration testing only. Unauthorized use against any network without explicit permission is illegal. You are responsible for your own actions.**

---

## Features

- **🔍 Automated AD Enumeration:** Discovers users, computers, groups, and trust relationships
- **🎯 Kerberoasting:** Identifies and attacks service accounts with SPNs
- **🔥 AS-REP Roasting:** Targets accounts with pre-authentication disabled
- **🛡️ ACL Analysis:** Finds misconfigured permissions for privilege escalation
- **🤖 AI-Driven Automation:** Intelligently chains attacks for maximum impact
- ** stealth Mode:** Operates slowly to evade detection

## Quick Start

### Prerequisites
- Kali Linux (recommended) or Python 3.8+
- A dedicated Active Directory lab environment

### Installation
```bash
git clone https://github.com/yourusername/cerberus.git
cd cerberus

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Full automated attack chain
python main.py -d lab.local -u user -p 'password' -dc 192.168.1.10 --all

# Enumeration only (safe)
python main.py -d lab.local -u user -p 'password' --enumerate
