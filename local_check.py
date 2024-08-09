#Author: Daniel Morales
#Version: 1.0

#Import section
import getpass
import subprocess
import logging
from os import uname
from tqdm import tqdm
from styles import Styles
from check_loader import CheckLoader
from osint_check import OsintCheck
from privesc_checks import PrivesChecks

class LocalCheck:
    def __init__(self, args):
        self.style =Styles()
        self.check_type = args.type
        self.username = getpass.getuser()
        self.hostname = uname().nodename
        if self.check_type =='config':
            self.check_list = CheckLoader.load_checks('sec_checks.json')
            self.style.color_print('[+] Load checks -> [OK]','green')
        else:
            self.check_list = PrivesChecks().get_checks()
            self.style.color_print('[+] Load Privilege escalation checks -> [OK]','green')
        self.password = getpass.getpass(f'\n[+] Introduce user {self.username} password: ')
        self.results = []

    def run_checks(self):
        self.style.color_print('\n[+] Analyzing host...','white')
        if self.check_type == 'config':
            self.run_config_checks()
        if self.check_type == 'privilege':
            self.run_privilege_checks()
                   
    def run_config_checks(self):
        check_results = []
        passed = 0
        risk_score = 'LOW'
        try:
            for check in tqdm(self.check_list,desc=f'Analyzing host: {self.hostname} ',ascii=' ░▒▓█'):
                command = f"echo {self.password} | sudo -S {check.get('command')}"
                valid_result = check.get('valid_result')
                output = subprocess.run(command, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if 'incorrect password attempt' in output.stderr:
                    logging.error("\n[*] ERROR: Wrong password")
                    break
                else:
                    if valid_result == 'No output' and not output.stdout.strip():
                        result ='pass'
                    else:
                        result = 'pass' if valid_result in output.stdout else 'fail'
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
            'hostname': self.hostname,
            'score': f'Passed {passed} of {len(self.check_list)}',
            'risk': risk_score,
            'check_res': check_results    
            })
        except OSError as e:
            logging.error(f"Command execution error : {e}")
            exit(1)

    def run_privilege_checks(self):
        privesc_results = []
        privesc_checks= self.check_list
        try:
            for check in tqdm(privesc_checks,desc=f'Analyzing host {self.hostname} ',ascii=' ░▒▓█'):
                if check['id'] == 'sudo_check':
                    command = f"echo {self.password} | sudo -S {check.get('command')}"
                    output = subprocess.run(command, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    sudo_result = 'not vulnerable' if 'NOPASSWD' not in output.stdout else 'vulnerable'
                    sudo_users = []
                    if sudo_result == 'vulnerable':
                        lines = output.stdout.split('\n')
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
                    output = subprocess.run(check['command'], shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    setuid_files = output.stdout.splitlines()
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
                    output = subprocess.run(check['command'], shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    kernel_version = output.stdout.strip()
                    exploit_result, exploit_details = OsintCheck.check_kernel_exploits(kernel_version)
                    privesc_results.append({
                        'id': check['id'],
                        'description': check['description'],
                        'remediation': check['remediation'],
                        'result': exploit_result,
                        'exploit_details': exploit_details
                    })

            self.results.append({
            'hostname': self.hostname,
            'privesc_res': privesc_results
            })
        except OSError as e:
            logging.error(f"Command execution error : {e}")
            exit(1)

    def get_results(self):
        return self.results
