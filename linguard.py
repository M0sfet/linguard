#Author: Daniel Morales
#Version: 1.0
#Description: Security check tool, analyze Linux based systems hardening configuration based on CIS4 benchmark and potentials privilege escalation paths


#Import section
import logging
import argparse
import styles
import ssh_connector

#Main class
class Linguard:
    def __init__(self):
        self.args = self.parse_arguments()
        self.style =styles.Styles('LINGUARD')
        self.run()

    #Argument parser
    def parse_arguments(self):
        parser = argparse.ArgumentParser(description="Linguard - Security configuration analysis tool")
        parser.add_argument('--targets', help="Path to the IP addresses list file")
        parser.add_argument('-t', '--type', choices=['config', 'privilege'], help='Type of security check to perform', required=True)
        parser.add_argument('-o', '--output', choices=['json', 'markdown'], help="Output file format")
        parser.add_argument('--result_path', help="Path for results file")
        return parser.parse_args()

    #Main method
    def run(self):
        self.style.ascii_banner()
        self.style.color_print('version: 1.0','yellow')
        #results = []
        if self.args.type == 'config':
            self.style.color_print('[+] Launching security check...','blue')
            target = ssh_connector.SSHConnector('172.17.0.2','test','Test1234','/home/m0sfet/.ssh/id_rsa')
            output=target.execute_command('ls /root')
            self.style.color_print(f'The output of last command is:\n{output}','magenta')
            target.close()
            #sec_check = SecurityCheck(self.args.targets)
            #results = sec_check.run_checks()
        elif self.args.type == 'privilege':
            self.style.color_print('[+] Launching privilege escalation check...','green')
            #presc_check = PrivEscCheck(self.args.targets)
            #results = presc_check.run_checks()
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
