# HardNIX – Linux Hardening Script

**HardNIX** is a Linux hardening script designed to improve system security through configurable levels of hardening. It generates detailed HTML reports, performs system and kernel hardening, configures firewall and PAM policies, and applies best practices for account and file security.  

> **Note:** This script has only been tested on Ubuntu. Users must carefully adapt the script to their environment, infrastructure, and specific needs before using it in production.

---

## Hardening Levels

The script provides four levels of hardening:

- **Minimal:** Basic security measures for test environments or low-risk workstations.  
- **Intermediate:** Additional hardening for standard servers and production workstations.  
- **Reinforced:** Stronger hardening for sensitive systems handling critical data.  
- **Elevated:** Maximum security, advanced auditing, and intrusion detection for high-risk systems.  

---

## Script Options

| Option | Description |
|--------|-------------|
| `-h`   | Display the help menu |
| `-m <level>` | Set the hardening level (`minimal`, `intermediate`, `reinforced`, `elevated`) |

---

## Screenshots

**Help menu**  
<img width="1413" height="899" alt="hardnix_help" src="https://github.com/user-attachments/assets/4599fd49-b0f3-476c-959e-d142fbb3691a" />


**Generated report**  
<img width="1840" height="790" alt="hardnix_report" src="https://github.com/user-attachments/assets/09a1a643-888d-4d0b-8d7c-2e9d7d51baec" />

---

## Usage

Run the script as root with the desired hardening level:

```bash
bash hardnix.sh -m <hardening_level>
```

## Features

- **Account and Password Hardening:** PAM configuration, password policies, automatic logout for inactivity.  
- **Firewall Management:** UFW configuration with default deny rules, logging, and essential ports allowed.  
- **Kernel Hardening:** ASLR, TOCTOU protections, Spectre/Meltdown mitigations, IOMMU activation, module restrictions.  
- **Filesystem Security:** Backup of important files, removal of SUID/SGID binaries, sticky bit enforcement, orphaned file detection.  
- **Logging and Auditing:** Auditd configuration, command execution monitoring, and sudoers default rules.  
- **Network Hardening:** IPv4/IPv6 restrictions, ARP and ICMP protections, ephemeral port configuration, SYN cookies.  
- **HTML Reporting:** Generates a world-readable report with a hardening score, system information, and applied measures.  

---

## Important Notes

- Users must review and adapt this script to match their own infrastructure and security requirements.  
- This script makes **system-wide changes**, including kernel and network parameters, which may impact functionality.  
- Always back up your system and test in a safe environment before deploying in production.  

---

## Disclaimer

This script is provided for **educational purposes only**. The author assumes **no responsibility** for any damage, data loss, or system malfunction caused by its use. Use at your own risk.
