# LINGUARD Report.
**Date:** 09/08/2024

## IP: 172.17.0.2

### Ports and Services
- **Port:** 22, **Service:** ssh, **Version:** OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)

### Privilege Escalation Check Results
- **ID:** sudo_check, **Description:** Review sudo configuration
  - **Result:** not vulnerable
- **ID:** setuid_check, **Description:** Find files with setuid enabled
  - **File with SETUID enabled:**  /usr/bin/nmap
  - **You should check:**   https://gtfobins.github.io/gtfobins/nmap
  - **Result:** vulnerable
- **ID:** kernel_check, **Description:** Check kernel version
  - **No known privilege escalation exploits found**
  - **Result:** not vulnerable

## IP: 172.17.0.3

### Ports and Services
- **Port:** 22, **Service:** ssh, **Version:** OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)

### Privilege Escalation Check Results
- **ID:** sudo_check, **Description:** Review sudo configuration
  - **Result:** not vulnerable
- **ID:** setuid_check, **Description:** Find files with setuid enabled
  - **File with SETUID enabled:**  /home/test/suid_test
  - **Result:** vulnerable
- **ID:** kernel_check, **Description:** Check kernel version
  - **No known privilege escalation exploits found**
  - **Result:** not vulnerable

## IP: 172.17.0.4

### Ports and Services
- **Port:** 22, **Service:** ssh, **Version:** OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)

### Privilege Escalation Check Results
- **ID:** sudo_check, **Description:** Review sudo configuration
  - **Result:** not vulnerable
- **ID:** setuid_check, **Description:** Find files with setuid enabled
  - **Result:** not vulnerable
- **ID:** kernel_check, **Description:** Check kernel version
  - **No known privilege escalation exploits found**
  - **Result:** not vulnerable
