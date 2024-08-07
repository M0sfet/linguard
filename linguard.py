#Author: Daniel Morales
#Version: 1.0
#Description: Security check tool, analyze Linux based systems hardening configuration based on CIS4 benchmark and potentials privilege escalation paths


#Import section
import argparse
import logging
from styles import Styles
from remote_check import RemoteCheck
from os import path


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
        parser.add_argument('-o', '--output', choices=['json', 'markdown'], help="Output file format, default: format JSON")
        parser.add_argument('-r','--result_path', help="Path for results file, default: execution path")
        args = parser.parse_args()
        if args.mode == "remote" and (not args.targets or not args.SSHuser or not args.SSHkey):
            parser.error("--target, --SSHuser and --SSHkey are required if --mode is set to 'remote'")
            parser.print_usage()
        if args.SSHuser.lower() == 'root':
            parser.error("SSH connection using root user is not allowed")
            parser.print_usage()
        return args

    #Main method
    def run(self):
        results = []
        self.style.ascii_banner('LINGUARD')
        self.style.color_print('version: 1.0.0','yellow')
        if self.args.mode == 'remote' and self.args.type == 'config':
            self.style.color_print('[+] Launching security check...','blue')
            remote_check = RemoteCheck(self.args)
            remote_check.run_checks()
            results = remote_check.get_results()
            for result in results:
                self.style.color_print(f'\n[+] SECURITY CHECK RESULTS: {result["ip"]}','white')
                if result['check_res'] == 'ERROR':
                    self.style.color_print('ERROR: Check commands execution failed','red')
                    break
                for check in result['check_res']:
                    if check['result'] == 'fail':
                        color = 'red'
                    else:
                        color ='green'
                    self.style.color_print(f'[+] Check {check["id"]}, Description: {check["description"]}. Result -> {check["result"]}',color)
                    if check['result'] == 'fail':
                        self.style.color_print(f'\t[*] Remediation: {check["remediation"]}','red')
        elif self.args.mode == 'remote' and self.args.type == 'privilege':
            self.style.color_print('[+] Launching privilege escalation check...','green')
            remote_check = RemoteCheck(self.args)
            remote_check.run_checks()
            results = remote_check.get_results()
            for result in results:
                self.style.color_print(f'\n[+] PRIVILEGE ESCALATION CHECK RESULTS: {result["ip"]}','white')
                for priv_res in result['privesc_res']:
                    if priv_res['result'] == 'fail':
                        color = 'red'
                    else:
                        color ='green'
                    self.style.color_print(f'[+] Check {priv_res["id"]}, Description: {priv_res["description"]}. Result -> {priv_res["result"]}',color)
                    if priv_res['result'] == 'fail' and priv_res['id'] == 'setuid_check':
                        if priv_res['details']:
                            for setuid_file in priv_res['details']:
                                self.style.color_print(f'\t[*] File with SETUID enabled: {setuid_file}','red')
                                self.style.color_print(f'\t[*] You should check: https://gtfobins.github.io/gtfobins/{path.basename(setuid_file)}','red')
                        self.style.color_print(f'\t[*] Remediation: {priv_res["remediation"]}','red')
                    elif priv_res['id'] == 'kernel_check':
                        self.style.color_print(f'\t[*] {priv_res["exploit_details"]}','green')

        #self.save_results(results)

    #Handle results
    def save_results(self, results):
        if self.args.output == 'json':
            self.save_to_json(results)
        elif self.args.output == 'markdown':
            self.save_to_markdown(results)

    def save_to_json(self, results):
        import json
        with open(self.args.results_path, 'w', encoding='UTF-8') as f:
            json.dump(results, f, indent=4)

    def save_to_markdown(self, results):
        with open(self.args.results_path, 'w', encoding='UTF-8') as f:
            f.write("# Linguard Results\n\n")
            for result in results:
                f.write(f"## Check ID: {result['id']}\n")
                f.write(f"**Result:** {result['result']}\n\n")

if __name__ == "__main__":
    Linguard()
