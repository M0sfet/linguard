#Author: Daniel Morales
#Version: 1.0

#Import section
import threading
import getpass
import re
import requests
import logging
from styles import Styles
from tqdm import tqdm
from nmap_scanner import NmapScanner
from ssh_connector import SSHConnector
from check_loader import CheckLoader

class RemoteCheck:
    def __init__(self, args):
        self.style =Styles()
        self.targets_path = args.targets
        self.check_type = args.type
        self.username = args.SSHuser
        self.key_path = args.SSHkey
        if self.check_type =='config':
            self.check_list = CheckLoader.load_checks('sec_checks.json')
            self.style.color_print('[+] Load checks -> [OK]','green')
        self.password = getpass.getpass(f'\n[+] Introduce user {self.username} password: ')
        self.targets = self.load_targets()
        self.reachable_hosts = self.scan_hosts()
        self.style.color_print('[+] Hosts port scan -> OK','green')
        self.results = []

    def load_targets(self):
        hosts=[]
        ip_pattern=re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        with open(self.targets_path, 'r', encoding='UTF-8') as file:
            ips=file.readlines()
        for ip in ips:
            if ip_pattern.match(ip.strip()):
                hosts.append(ip.strip())
        return hosts

                       
    def run_checks(self):
        threads = []
        for host in self.reachable_hosts:
            ssh_enabled = False
            for ports in host['ports']:
                if ports['port'] == 22:
                    ssh_enabled = True
            if  ssh_enabled:
                if len(threads) <= 3:
                    thread = threading.Thread(target=self.run_checks_on_host, args=(host['ip'],))
                    thread.start()
                    threads.append(thread)
                    for thread in threads:
                        thread.join()
            else:
                self.style.color_print(f'[+] Host: {host["ip"]} Unreachable or SSH service not enabled','red')

    def scan_hosts(self):
        self.style.color_print('\n[+] Scanning hosts ports...','white')
        nmap_scanner = NmapScanner(self.targets)
        return nmap_scanner.scan()

    def run_checks_on_host(self, host):
        ssh = SSHConnector(host, self.username, self.key_path, self.password)
        if self.check_type == 'config':
            self.run_config_checks(ssh)
        elif self.check_type == 'privilege':
            self.run_privilege_checks(ssh)

    def run_config_checks(self, ssh):
        check_results = []
        for check in tqdm(self.check_list,desc=f'Analyzing host: {ssh.get_ip()} ',ascii=' ░▒▓█'):
            command = check.get('command')
            valid_result = check.get('valid_result')
            output = ssh.execute_command(command,use_sudo=True)
            if output == 'command_exec_error':
                check_results = 'ERROR'
                break
            else:
                result = 'pass' if valid_result in output else 'fail'
                check_results.append({
                    'id': check.get('id'),
                    'description': check.get('description'),
                    'remediation': check.get('remediation'),
                    'result': result
                })
        self.results.append({
        'ip': ssh.get_ip(),
        'check_res': check_results    
        })
        ssh.close()


    def run_privilege_checks(self, ssh):
        privesc_results = []
        privesc_checks=[
            {'id': 'sudo_check',
             'command' : 'sudo -l',
             'description': 'Review sudo configuration',
             'remediation': 'Delete NOPASSWD configuration in sudoers file'
            },
            {'id': 'setuid_check',
             'command' : 'find / -perm -4000 -type f 2>/dev/null',
             'description': 'Find files with setuid enabled',
             'remediation': 'Review and disable the unmnecesary setuid rights over the files'
            },
            {'id': 'kernel_check',
             'command' : 'uname -r',
             'description': 'Check kernel version',
             'remediation': 'Upgrade kernel version to a not vulnerable version'
            }
        ]
        for check in tqdm(privesc_checks,desc=f'Analyzing host: {ssh.get_ip()} ',ascii=' ░▒▓█'):
            if check['id'] == 'sudo_check':
                output = ssh.execute_command(check['command'],True)
                sudo_result = 'pass' if 'NOPASSWD' not in output else 'fail'
                privesc_results.append({
                    'id': check['id'],
                    'description': check['description'],
                    'remediation': check['remediation'],
                    'result': sudo_result
                })
            if check['id'] == 'setuid_check':
                valid_setuid_files =(
                    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
                    "/usr/lib/openssh/ssh-keysign",
                    "/usr/bin/gpasswd",
                    "/usr/bin/mount",
                    "/usr/bin/su",
                    "/usr/bin/chsh",
                    "/usr/bin/umount",
                    "/usr/bin/newgrp",
                    "/usr/bin/passwd",
                    "/usr/bin/chfn",
                    "/usr/bin/sudo")
                not_valid_setuid_file = False
                setuid_files_unvalid=[]
                output = ssh.execute_command(check['command'])
                setuid_files = output.splitlines()
                for file in setuid_files:
                    if file not in valid_setuid_files:
                        not_valid_setuid_file = True
                        setuid_files_unvalid.append(file)
                setuid_result = 'fail' if not_valid_setuid_file else 'pass'
                privesc_results.append({
                    'id': check['id'],
                    'description': check['description'],
                    'remediation': check['remediation'],
                    'result': setuid_result,
                    'details': setuid_files_unvalid
                })
            if check['id'] == 'kernel_check':
                output = ssh.execute_command(check['command'])
                kernel_version = output.strip()
                exploit_result, exploit_details = self.check_kernel_exploits(kernel_version)
                kernel_result = 'pass' if 'NOPASSWD' not in output else 'fail'
                privesc_results.append({
                    'id': check['id'],
                    'description': check['description'],
                    'remediation': check['remediation'],
                    'result': exploit_result,
                    'exploit_details': exploit_details
                })

        self.results.append({
        'ip': ssh.get_ip(),
        'privesc_res': privesc_results
        })

    def check_kernel_exploits(self, version):
        version_parts = version.split('.')
        major = version_parts[0]
        minor = version_parts[1] if len(version_parts) > 1 else '0'
        query_version = f"{major}.{minor}"
        url = f"https://www.exploit-db.com/search?q=+{query_version}&type=local&platform=linux_x86-64" 
        try:
            response = requests.get(url)
            if 'No results found' in response.text:
                return 'pass', 'No known exploits found'
            exploits = []
            for line in response.text.splitlines():
                if 'Privilege Escalation' in line:
                    exploit_url = f"https://www.exploit-db.com{line.split('href=')[1].split('')[0]}"
                    exploits.append(exploit_url)
            
            if exploits:
                return 'fail', exploits
            else:
                return 'pass', 'No known privilege escalation exploits found'
        
        except requests.RequestException as e:
            logging.error(f"Error checking exploits for kernel version {version}: {e}")
            return 'fail', 'Error checking exploits'

    def get_results(self):
        return self.results
