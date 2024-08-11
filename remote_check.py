#Author: Daniel Morales
#Version: 1.0

#Import section
import threading
import getpass
import re
from os import _exit
from tqdm import tqdm
from styles import Styles
from nmap_scanner import NmapScanner
from ssh_connector import SSHConnector
from check_loader import CheckLoader
from osint_check import OsintCheck
from privesc_checks import PrivesChecks

class RemoteCheck:
    def __init__(self, args):
        self.style =Styles()
        self.targets_path = args.targets
        self.check_type = args.type
        self.username = args.SSHuser
        self.key_path = args.SSHkey
        self.max_threads = args.maxthreads
        if self.check_type =='config':
            self.check_list = CheckLoader.load_checks(args.checks)
            self.style.color_print('[+] Load checks -> [OK]','green')
        else:
            self.check_list = PrivesChecks().get_checks()
            self.style.color_print('[+] Load Privilege escalation checks -> [OK]','green')
        self.password = getpass.getpass(f'\n[+] Introduce user {self.username} password: ')
        self.targets = self.load_targets()
        self.reachable_hosts = self.scan_hosts()
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
        self.style.color_print('\n[+] Analyzing hosts...','white')
        for host in self.reachable_hosts:
            ssh_enabled = False
            for ports in host['ports']:
                if ports['port'] == 22:
                    ssh_enabled = True
            if  ssh_enabled:
                if len(threads) <= self.max_threads:
                    thread = threading.Thread(target=self.run_checks_on_host, args=(host['ip'],host['ports']))
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

    def run_checks_on_host(self, host, ports):
        ssh = SSHConnector(host, self.username, self.key_path, self.password)
        if self.check_type == 'config':
            self.run_config_checks(ssh,ports)
        elif self.check_type == 'privilege':
            self.run_privilege_checks(ssh,ports)

    def run_config_checks(self, ssh, ports):
        check_results = []
        passed = 0
        risk_score = 'LOW'
        try:
            for check in tqdm(self.check_list,desc=f'Analyzing host {ssh.get_ip()} ',ascii=' ░▒▓█'):
                command = check.get('command')
                valid_result = check.get('valid_result')
                output = ssh.execute_command(command,use_sudo=True)
                if output == 'command_exec_error':
                    raise Exception("Command Execution Error")
                else:
                    if valid_result == 'No output' and not output.strip():
                        result ='pass'
                    else:
                        result = 'pass' if valid_result in output else 'fail'
                    passed = passed + 1 if result == 'pass' else passed
                    check_results.append({
                        'id': check.get('id'),
                        'description': check.get('description'),
                        'remediation': check.get('remediation'),
                        'sec_standard': check.get('sec_standard'),
                        'severity': check.get('severity'),
                        'result': result
                    })
            for check in check_results:
                if 'high' in check['severity'] and check['result'] == 'fail':
                    risk_score = 'HIGH'
                    break
                if 'medium' in check['severity']and check['result'] == 'fail':
                    risk_score = 'MEDIUM'
            self.results.append({
            'ip': ssh.get_ip(),
            'ports': ports,
            'score': f'Passed {passed} of {len(self.check_list)}',
            'risk': risk_score,
            'check_res': check_results    
            })
            ssh.close()
        except Exception as e:
            print(f'[*] ERROR: {e}')
            _exit(1)


    def run_privilege_checks(self, ssh, ports):
        privesc_results = []
        privesc_checks= self.check_list
        for check in tqdm(privesc_checks,desc=f'Analyzing host {ssh.get_ip()} ',ascii=' ░▒▓█'):
            if check['id'] == 'sudo_check':
                output = ssh.execute_command(check['command'],True)
                sudo_result = 'not vulnerable' if 'NOPASSWD' not in output else 'vulnerable'
                sudo_users = []
                if sudo_result == 'vulnerable':
                    lines = output.split('\n')
                    sudo_details = [line for line in lines if 'NOPASSWD' in line]
                    for user in sudo_details:
                        sudo_users.append(user.split()[0])     
                privesc_results.append({
                    'id': check['id'],
                    'description': check['description'],
                    'remediation': check['remediation'],
                    'result': sudo_result,
                    'sudo_users': sudo_users
                })
            if check['id'] == 'setuid_check':
                valid_setuid_files = PrivesChecks().get_valid_setuid_files()
                not_valid_setuid_file = False
                setuid_files_unvalid=[]
                setuid_gtfobin = []
                output = ssh.execute_command(check['command'])
                setuid_files = output.splitlines()
                for setuid_file in setuid_files:
                        if setuid_file.split('/')[-1] not in valid_setuid_files:
                            not_valid_setuid_file = True
                            setuid_files_unvalid.append(setuid_file)
                            url_gtfobin = OsintCheck.check_gtfobins_exploits(setuid_file)
                            if url_gtfobin != 'not_found':
                                setuid_gtfobin.append(url_gtfobin)
                setuid_result = 'vulnerable' if not_valid_setuid_file else 'not vulnerable'
                privesc_results.append({
                    'id': check['id'],
                    'description': check['description'],
                    'remediation': check['remediation'],
                    'result': setuid_result,
                    'details': setuid_files_unvalid,
                    'setuid_gtfobin': setuid_gtfobin
                })
            if check['id'] == 'kernel_check':
                output = ssh.execute_command(check['command'])
                kernel_version = output.strip()
                exploit_result, exploit_details = OsintCheck.check_kernel_exploits(kernel_version)
                privesc_results.append({
                    'id': check['id'],
                    'description': check['description'],
                    'remediation': check['remediation'],
                    'result': exploit_result,
                    'exploit_details': exploit_details
                })

        self.results.append({
        'ip': ssh.get_ip(),
        'ports': ports,
        'privesc_res': privesc_results
        })

    def get_results(self):
        return self.results
