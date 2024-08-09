# LINGUARD
Perform an analysis of the security configuration (hardening) of Linux-based systems using the controls defined by the user, fully allowing definition of a customized security hardening control template mixing infosec standards such as ISO 27001, PCI-DSS or CIS guidelines for instance. Also, allows a basic analysis of potential privilege escalation paths in the audited systems. All the results will be saved into a report in JSON or MARKDOWN format.
## INSTALLATION
Just clone the repository: 

    git clone https://github.com/M0sfet/linguard.git

Once done install the needed libraries with the command:

    pip -r requirements.txt


## RUNNING LINGUARD

-h|--help shows the usage

```
python3 linguard.py -h
usage: linguard.py [-h] -m {local,remote} -t {config,privilege} [-l TARGETS] [-u SSHUSER] [-k SSHKEY] [-o {json,markdown}] [-r RESULTS_PATH]

Linguard - Security configuration analysis tool

options:
  -h, --help            show this help message and exit
  -m {local,remote}, --mode {local,remote}
                        Type of scan - Required
  -t {config,privilege}, --type {config,privilege}
                        Type of security check to perform - Required
  -l TARGETS, --targets TARGETS
                        Path to the IP addresses list file (required if mode is remote)
  -u SSHUSER, --SSHuser SSHUSER
                        User for connecting to remote hosts via SSH (required if mode is remote)
  -k SSHKEY, --SSHkey SSHKEY
                        Private key file for connecting to remote hosts via SSH (required if mode is remote)
  -o {json,markdown}, --output {json,markdown}
                        Output file format
  -r RESULTS_PATH, --results_path RESULTS_PATH
                        Path for results file, default: execution reports/date_results
```

## Options

There are two modes:
+ Local: Run checks on the local machine where the application is being executed.
+ Remote: Run checks on remote targets via a SSH connection specified in a file list passed as an argument.

Once the mode have been specified it can run two type of checks:
+ config: Security checks specified in the file db/sec_checks.json
+ privilege: Potential privilege escalation paths ,currently supporting the following checks: 
    + Unsecure sudo privileges (NOPASSWD). 
    + Abnormal setuid files present in the system, it will also check if there is an entry for that file in GTFObins (https://gtfobins.github.io/), and if is that so it will save the link in the report.
    + Vulnerable kernel version: It will check the presence of public esploits using exploit-db online database.

Remote mode integrates with NMAP (https://nmap.org/) for port scanning validating the SSH service port i open and reachable, but it will also perform a service fingerprinting of the 100 most used TCP ports ans that information will be included in the report. 
**Therefore NMAP should be installed in the system for launching check scans over remote targets.**

For the remote mode the checks will be executed via a SSH connection the requirements are:

+ **Valid sudo-enabled user** (root user is not allowed) that can run privilege commands in the remote targets using sudo. 

+ **RSA private key in the authorized_keys file of the remote targets**: For security reason this will be the only supported authentication method supported.

Finally you can select the report format between JSON that can be easily imported in other tools or MARKDOWN as a human readable format.

if you don´t specify the desired format and path to save the report by default the application will generate a JSON report and will save it in /reports/{date}results

## Example

Running a remote privilege check over 4 targets default report format would be JSON as wasn´t specified in the options.

```
python3 linguard.py -m remote -t config -l targets.txt -u test -k /home/m0sfet/.ssh/id_rsa
   __    _____   __________  _____    ____  ____
   / /   /  _/ | / / ____/ / / /   |  / __ \/ __ \
  / /    / //  |/ / / __/ / / / /| | / /_/ / / / /
 / /____/ // /|  / /_/ / /_/ / ___ |/ _, _/ /_/ /
/_____/___/_/ |_/\____/\____/_/  |_/_/ |_/_____/


version: 1.0.0

Press ctrl-c to abort execution

Start time: 09/08/2024 17:46:09

[+] Launching security check...

[+] Loading check file...
[+] Load checks -> [OK]


[+] Introduce user test password:

[+] Scanning hosts ports...

Scanning hosts: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4/4 [00:07<00:00,  1.80s/it]
[+] Analyzing hosts...

Analyzing host 172.17.0.2 : 100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 15/15 [00:01<00:00,  9.18it/s]
Analyzing host 172.17.0.3 : 100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 15/15 [00:01<00:00, 13.31it/s]
Analyzing host 172.17.0.4 : 100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 15/15 [00:01<00:00, 13.17it/s]
[+] Host: 172.17.0.5 Unreachable or SSH service not enabled


[+] Generating result report in JSON format...

[+] Report saved in : reports/09082024_results_sec.json

End time: 09/08/2024 17:46:24
```

## Security check database

The security checks are fully customizable, for instance it will allow to create your own subset of checks mixing several controls from different infosec standards such as ISO 27001, PCI-DSS or technical guidelines such as CIS benchmark.Just need to edit the check db file sec_checks.json under db folder. You will find a sample file in this repository its structure must be followed to add or modify any check.
Linguard will validate the file strcuture automatically upon start and also it will validate the commands specified in the checks to avoid the potential misuse of the tool.

```
[
    {
        "id": 1,
        "description": "Verify that the SSH protocol is using version 2",
        "command": "grep '^Protocol' /etc/ssh/sshd_config",
        "valid_result": "Protocol 2",
        "remediation": "Edit the SSH configuration file to enforce SSH protocol 2 by adding or modifying the line 'Protocol 2'.",
        "sec_standard": "CIS Control 5.2.7 - Ensure SSH Protocol is set to 2",
        "severity": "high"
    },
    {
        "id": 2,
        "description": "Check if the firewall is active",
        "command": "ufw status",
        "valid_result": "Status: active",
        "remediation": "Activate the firewall using 'ufw enable'.",
        "sec_standard": "CIS Control 9.1.1 - Ensure a firewall is enabled; PCI-DSS Requirement 1.1 - Install and maintain a firewall configuration to protect cardholder data",
        "severity": "high"
    }
]
```
**Important note: In case the valid result output from the check command is empty please use the string  'No output' as value for the valid_result field in the check database.**

## Reports

The report could be generated in two flavours:

+ JSON: Easy to use for another application
```
[
    {
        "ip": "172.17.0.2",
        "ports": [
            {
                "port": 22,
                "service": "ssh",
                "version": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)"
            }
        ],
        "score": "Passed 7 of 15",
        "risk": "HIGH",
        "check_res": [
            {
                "id": 1,
                "description": "Verify that the SSH protocol is using version 2",
                "remediation": "Edit the SSH configuration file to enforce SSH protocol 2 by adding or modifying the line 'Protocol 2'.",
                "sec_standard": "CIS Control 5.2.7 - Ensure SSH Protocol is set to 2",
                "severity": "high",
                "result": "pass"
            },
            {
                "id": 2,
                "description": "Check if the firewall is active",
                "remediation": "Activate the firewall using 'ufw enable'.",
                "sec_standard": "CIS Control 9.1.1 - Ensure a firewall is enabled; PCI-DSS Requirement 1.1 - Install and maintain a firewall configuration to protect cardholder data",
                "severity": "high",
                "result": "pass"
            }
        ]
    }
]
```
+ MARKDOWN: More human readable.

# LINGUARD Report.
**Date:** 09/08/2024

## IP: 172.17.0.2

### Ports and Services
- **Port:** 22, **Service:** ssh, **Version:** OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)

#### Score: Passed 7 of 15

#### Risk: HIGH

### Security Configuration Check Results
- **ID:** 1, **Description:** Verify that the SSH protocol is using version 2
  - **Result:** pass
  - **Infosec standards reference:** CIS Control 5.2.7 - Ensure SSH Protocol is set to 2
- **ID:** 2, **Description:** Check if the firewall is active
  - **Result:** pass
  - **Infosec standards reference:** CIS Control 9.1.1 - Ensure a firewall is enabled; PCI-DSS Requirement 1.1 - Install and maintain a firewall configuration to protect cardholder data
- **ID:** 3, **Description:** Ensure password expiration is configured
  - **Result:** fail
  - **Remediation:** Set the maximum password age to 90 days by adding or modifying the line 'PASS_MAX_DAYS 90' in /etc/login.defs.
  - **Severity:** medium
  - **Infosec standards reference:** CIS Control 5.4.1.1 - Ensure password expiration is 365 days or less; PCI-DSS Requirement 8.2.4 - Passwords/phrases must be changed at least once every 90 days