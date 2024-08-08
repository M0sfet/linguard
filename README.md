# LINGUARD
Perform an analysis of the security configuration (hardening) of Linux-based systems using the controls defined by the user, fully allowing definition of a customized security hardening control template. Also, allows a basic analysis of potential privilege escalation paths in the audited systems. All the results will be saved into a report in JSON or MARKDOWN format.
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
    + Abnormal setuid files present in the system, it will also check if there is an entry for that file in GTFObins, and if is that so it will save the link in the report.
    + Vulnerable kernel version: It will check the presence of public esploits using exploit-db online database.

For the remote mode the checks will be executed via a SSH connection, a valid sudo-enabled user will be needed, also for security reason the only supported authentication method is thru a RSA private key previously added in the authorized_keys file of the remote targets.

Finally you can select the report format between JSON that can be easily imported in other tools or MARKDOWN as a human readable format.

if you don´t specify the desired format and path to save the report by default the application will generate a JSON report and will save it in /reports/{date}results

## Example

Running a remote privilege check over 4 targets selecting markdown as the desired report format.

```
   __    _____   __________  _____    ____  ____
   / /   /  _/ | / / ____/ / / /   |  / __ \/ __ \
  / /    / //  |/ / / __/ / / / /| | / /_/ / / / /
 / /____/ // /|  / /_/ / /_/ / ___ |/ _, _/ /_/ /
/_____/___/_/ |_/\____/\____/_/  |_/_/ |_/_____/


version: 1.0.0

Press ctrl-c to abort execution

[+] Launching privilege escalation check...

[+] Load Privilege escalation checks -> [OK]


[+] Introduce user test password:

[+] Scanning hosts ports...

Scanning hosts: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4/4 [00:06<00:00,  1.70s/it]
[+] Analyzing hosts...

Analyzing host 172.17.0.2 : 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 3/3 [00:00<00:00,  8.64it/s]
Analyzing host 172.17.0.3 : 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 3/3 [00:00<00:00,  7.24it/s]
Analyzing host 172.17.0.4 : 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 3/3 [00:00<00:00,  5.01it/s]
[+] Host: 172.17.0.5 Unreachable or SSH service not enabled


[+] Generating result report in MARKDOWN format...


[+] Report created succesfully, saved in : reports/09082024_results_privesc.md
```