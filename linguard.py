#Author: Daniel Morales
#Version: 1.0
#Description: Security check tool, analyze Linux based systems hardening configuration based on CIS4 benchmark and potentials privilege escalation paths


#Import section
import argparse
import logging
import json
import signal
from styles import Styles
from local_check import LocalCheck
from remote_check import RemoteCheck
from datetime import datetime


#Handling user press ctrl-c
def user_abort(sig, frame):
    print("\n\n[+] User aborted execution")
    exit(0)

signal.signal(signal.SIGINT,user_abort)

#Main class
class Linguard:
    def __init__(self):
        self.args = self.parse_arguments()
        self.style =Styles()
        self.run()

    #Argument parser
    def parse_arguments(self):
        parser = argparse.ArgumentParser(description="Linguard - Security configuration analysis tool")
        parser.add_argument('-m','--mode',choices=['local','remote'],help='Type of scan',required=True)
        parser.add_argument('-t', '--type', choices=['config', 'privilege'], help='Type of security check to perform', required=True)
        parser.add_argument('-l','--targets', help="Path to the IP addresses list file (required if mode is remote)")
        parser.add_argument('-u','--SSHuser', help="User for connecting to remote hosts via SSH")
        parser.add_argument('-k','--SSHkey', help="Private key file for connecting to remote hosts via SSH")
        parser.add_argument('-o', '--output', choices=['json', 'markdown'], help="Output file format", default='json')
        parser.add_argument('-r','--results_path', help="Path for results file, default: execution reports/date_results",default=f'reports/{datetime.now().strftime("%d%m%Y")}_results')
        args = parser.parse_args()
        if args.mode == "remote" and (not args.targets or not args.SSHuser or not args.SSHkey):
            parser.error("--target, --SSHuser and --SSHkey are required if --mode is set to 'remote'")
            parser.print_usage()
        if args.SSHuser:
            if args.SSHuser.lower() == 'root':
                parser.error("SSH connection using root user is not allowed")
                parser.print_usage()
            if len(args.SSHuser) > 20  or len(args.results_path) > 40:
                parser.error("Argument too long")
                parser.print_usage()
        if args.mode == "local" and (args.targets or args.SSHuser or args.SSHkey):
            parser.error("--target, --SSHuser and --SSHkey are not required if --mode is set to 'local'")
            parser.print_usage()
        if len(args.results_path) > 40:
            parser.error("Argument too long")
            parser.print_usage()
        return args

    #Main method
    def run(self):
        self.style.ascii_banner('LINGUARD')
        self.style.color_print('version: 1.0.0','yellow')
        self.style.color_print('Press ctrl-c to abort execution','yellow')
        self.style.color_print(f'Start time: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}','yellow')
        if self.args.type == 'config':
            self.style.color_print('[+] Launching security check...','cyan')
        if self.args.type == 'privilege':
            self.style.color_print('[+] Launching privilege escalation check...','cyan')
        if self.args.mode == 'remote':
            remote_check = RemoteCheck(self.args)
            remote_check.run_checks()
            self.save_results(results = remote_check.get_results())
        if self.args.mode == 'local':
            local_check = LocalCheck(self.args)
            local_check.run_checks()
            self.save_results(results = local_check.get_results())
        self.style.color_print(f'End time: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}','yellow')

    #Handle results
    def save_results(self, results):
        if self.args.output == 'json':
            self.save_to_json(results)
        elif self.args.output == 'markdown':
            self.save_to_markdown(results)

    def save_to_json(self, results):
        try:
            self.style.color_print(f'\n[+] Generating result report in JSON format...','white')
            if not self.args.results_path.endswith('.json'):
                file_name = self.args.results_path+'_privesc.json' if self.args.type == 'privilege' else self.args.results_path+'_sec.json'
            else:
                file_name = self.args.results_path
            with open(file_name, 'w', encoding='UTF-8') as f:
                json.dump(results, f, indent=4)
            self.style.color_print(f'[+] Report saved in : {file_name}','white')
        except PermissionError:
            logging.error("\n[*] ERROR: Can not write the file, review filesystem permissions")
            exit(1)

    def save_to_markdown(self, results):
        md_content = "# LINGUARD Report.\n" 
        md_content += f"**Date:** {datetime.now().strftime('%d/%m/%Y')}\n"
        for result in results:
            if self.args.mode == 'remote':
                md_content += f"\n## IP: {result['ip']}\n"
                md_content += "\n### Ports and Services\n"
                for port in result['ports']:
                    md_content += f"- **Port:** {port['port']}, **Service:** {port['service']}, **Version:** {port['version']}\n"
            else:
                md_content += f"\n## HOSTNAME: {result['hostname']}\n"
            if self.args.type == 'config':
                md_content += f"\n#### Score: {result['score']}\n"
                md_content += f"\n#### Risk: {result['risk']}\n"
            if self.args.type == 'config':
                md_content += "\n### Security Configuration Check Results\n"
                for check in result['check_res']:
                    md_content += f"- **ID:** {check['id']}, **Description:** {check['description']}\n"
                    md_content += f"  - **Result:** {check['result']}\n"
                    if check['result'] == 'fail':
                        md_content += f"  - **Remediation:** {check['remediation']}\n"
                        md_content += f"  - **Severity:** {check['severity']}\n"
                    md_content += f"  - **Infosec standards reference:** {check['sec_standard']}\n"
            elif self.args.type == 'privilege':
                md_content += "\n### Privilege Escalation Check Results\n"
                for check in result['privesc_res']:
                    md_content += f"- **ID:** {check['id']}, **Description:** {check['description']}\n"
                    if check['result'] == 'vulnerable' and check['id'] == 'setuid_check':
                        if check['details']:
                            for setuid_file in check['details']:
                                md_content += f"  - **File with SETUID enabled:**  {setuid_file}\n"
                                if check['setuid_gtfobin']:
                                    for url in check['setuid_gtfobin']:
                                        md_content += f"  - **You should check:**  {url}\n"
                    elif check['id'] == 'kernel_check':
                        md_content += f"  - **{check['exploit_details']}**\n"
                    elif check['id'] == 'sudo_check' and check['sudo_users']:
                        for sudo_user in check['sudo_users']:
                            md_content += f"  - **Unsecured sudo users:**  {sudo_user}\n"
                        md_content += f"  - **Remediation:** {check['remediation']}\n"
                    md_content += f"  - **Result:** {check['result']}\n" 
        try:
            self.style.color_print(f'\n[+] Generating result report in MARKDOWN format...','white')
            if not self.args.results_path.endswith('.md'):
                file_name = self.args.results_path+'_privesc.md' if self.args.type == 'privilege' else self.args.results_path+'_sec.md'
            else:
                file_name = self.args.results_path
            with open(file_name, 'w', encoding='UTF-8') as f:
                f.write(md_content)
            self.style.color_print(f'[+] Report saved in : {file_name}','white')
        except PermissionError:
            logging.error("\n[*] ERROR: Can not write the file, review filesystem permissions")
            exit(1)
            
if __name__ == "__main__":
    Linguard()
