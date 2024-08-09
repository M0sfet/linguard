# LINGUARD Report.
**Date:** 09/08/2024

## HOSTNAME: Jupiter

#### Score: Passed 1 of 15

#### Risk: HIGH

### Security Configuration Check Results
- **ID:** 1, **Description:** Verify that the SSH protocol is using version 2
  - **Result:** fail
  - **Remediation:** Edit the SSH configuration file to enforce SSH protocol 2 by adding or modifying the line 'Protocol 2'.
  - **Severity:** high
  - **Infosec standards reference:** CIS Control 5.2.7 - Ensure SSH Protocol is set to 2
- **ID:** 2, **Description:** Check if the firewall is active
  - **Result:** fail
  - **Remediation:** Activate the firewall using 'ufw enable'.
  - **Severity:** high
  - **Infosec standards reference:** CIS Control 9.1.1 - Ensure a firewall is enabled; PCI-DSS Requirement 1.1 - Install and maintain a firewall configuration to protect cardholder data
- **ID:** 3, **Description:** Ensure password expiration is configured
  - **Result:** fail
  - **Remediation:** Set the maximum password age to 90 days by adding or modifying the line 'PASS_MAX_DAYS 90' in /etc/login.defs.
  - **Severity:** medium
  - **Infosec standards reference:** CIS Control 5.4.1.1 - Ensure password expiration is 365 days or less; PCI-DSS Requirement 8.2.4 - Passwords/phrases must be changed at least once every 90 days
- **ID:** 4, **Description:** Check if iptables firewall rules are configured
  - **Result:** fail
  - **Remediation:** Configure iptables with appropriate firewall rules to secure the system.
  - **Severity:** high
  - **Infosec standards reference:** CIS Control 9.2.1 - Ensure iptables is installed and configured; PCI-DSS Requirement 1.2 - Build firewall and router configurations that restrict connections between untrusted networks and any system components in the cardholder data environment.
- **ID:** 5, **Description:** Verify that the system has no empty passwords
  - **Result:** pass
  - **Infosec standards reference:** CIS Control 5.4.1.4 - Ensure no empty passwords; PCI-DSS Requirement 8.2.6 - Review all user accounts to ensure that all users have a strong password set
- **ID:** 6, **Description:** Ensure root login is disabled over SSH
  - **Result:** fail
  - **Remediation:** Disable root login over SSH by setting 'PermitRootLogin no' in the SSH configuration.
  - **Severity:** high
  - **Infosec standards reference:** CIS Control 5.2.8 - Ensure SSH root login is disabled
- **ID:** 7, **Description:** Verify that audit logging is enabled
  - **Result:** fail
  - **Remediation:** Enable audit logging by installing and starting the auditd service.
  - **Severity:** medium
  - **Infosec standards reference:** CIS Control 8.1.1 - Ensure auditd is installed; ISO 27001 A.12.4 - Logging and monitoring
- **ID:** 8, **Description:** Ensure that password complexity requirements are enforced
  - **Result:** fail
  - **Remediation:** Configure the PAM module 'pam_pwquality.so' in '/etc/pam.d/common-password' to enforce password complexity requirements, such as minimum length and the inclusion of uppercase, lowercase, numbers, and special characters.
  - **Severity:** medium
  - **Infosec standards reference:** CIS Control 5.3.1 - Ensure password creation requirements are configured; PCI-DSS Requirement 8.2.3 - Implement and enforce password complexity requirements
- **ID:** 9, **Description:** Ensure the system has no world-writable files
  - **Result:** fail
  - **Remediation:** Remove world-writable permissions from files identified by the command.
  - **Severity:** medium
  - **Infosec standards reference:** CIS Control 1.1.1 - Ensure no world-writable files exist; PCI-DSS Requirement 6.4.3 - Ensure that only secure services, protocols, and daemons are enabled
- **ID:** 10, **Description:** Check for the presence of unused user accounts
  - **Result:** fail
  - **Remediation:** Disable or remove user accounts that have not been used in the last 365 days.
  - **Severity:** low
  - **Infosec standards reference:** CIS Control 5.4.4 - Ensure inactive accounts are disabled; PCI-DSS Requirement 8.1.4 - Remove/disable inactive user accounts within 90 days
- **ID:** 11, **Description:** Ensure password hashing algorithm is SHA-512
  - **Result:** fail
  - **Remediation:** Configure the system to use SHA-512 by running 'authconfig --passalgo=sha512 --update'.
  - **Severity:** high
  - **Infosec standards reference:** CIS Control 5.3.2 - Ensure password hashing algorithm is SHA-512; PCI-DSS Requirement 8.2.1 - Passwords/phrases must be securely stored using strong cryptography
- **ID:** 12, **Description:** Verify that the file system is encrypted (Full Disk Encryption)
  - **Result:** fail
  - **Remediation:** Implement full disk encryption (FDE) to protect data at rest.
  - **Severity:** high
  - **Infosec standards reference:** CIS Control 1.7.1.1 - Ensure that the system uses full disk encryption (FDE); PCI-DSS Requirement 3.4 - Render all data unreadable anywhere it is stored
- **ID:** 13, **Description:** Check if a system of endpoint protection (EDR) is installed
  - **Result:** fail
  - **Remediation:** Install and configure an appropriate EDR solution for the system.
  - **Severity:** high
  - **Infosec standards reference:** ISO 27001 A.12.6.2 - Protection against malware; PCI-DSS Requirement 5 - Use and regularly update antivirus software or programs
- **ID:** 14, **Description:** Ensure time synchronization is configured
  - **Result:** fail
  - **Remediation:** Enable and configure NTP or another time synchronization service.
  - **Severity:** low
  - **Infosec standards reference:** CIS Control 6.1.2 - Ensure that the time synchronization service is running; ISO 27001 A.12.4.3 - Synchronize clocks of all relevant information processing systems within the organization
- **ID:** 15, **Description:** Verify that the system uses strong ciphers
  - **Result:** fail
  - **Remediation:** Configure the SSH server to use strong ciphers by updating the 'Ciphers' directive in /etc/ssh/sshd_config.
  - **Severity:** high
  - **Infosec standards reference:** CIS Control 5.2.12 - Ensure that strong ciphers are used; PCI-DSS Requirement 4.1 - Use strong cryptography and security protocols
