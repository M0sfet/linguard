#Author: Daniel Morales
#Version: 1.0

#Import section
import threading
import getpass
from styles import Styles
from tqdm import tqdm
from nmap_scanner import NmapScanner
from ssh_connector import SSHConnector
from check_loader import CheckLoader

class RemoteCheck:
    def __init__(self, args):
        self.targets_path = args.targets
        self.check_type = args.type
        self.username = args.SSHuser
        self.key_path = args.SSHkey
        self.password = getpass.getpass(f'Por favor introduce la contraseña para el usuario {self.username}: ')
        self.targets = self.load_targets()
        self.reachable_hosts = self.scan_hosts()
        self.style =Styles()
        self.results = []

    def load_targets(self):
        hosts=[]
        with open(self.targets_path, 'r', encoding='UTF-8') as file:
            ips=file.readlines()
        for ip in ips:
            hosts.append(ip.strip())
        return hosts

                       
    def run_checks(self):
        threads = []
        for host in self.reachable_hosts:
            ssh_enabled = False
            print('\n')
            self.style.color_print(f'[+] Host escaneado: {host["ip"]}','yellow')
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
        nmap_scanner = NmapScanner(self.targets)
        return nmap_scanner.scan()

    def run_checks_on_host(self, host):
        ssh = SSHConnector(host, self.username, self.key_path, self.password)
        if self.check_type == 'config':
            self.run_config_checks(ssh)
        elif self.check_type == 'privilege':
            self.run_privilege_checks(ssh)

    def run_config_checks(self, ssh):
        #checks = CheckLoader.load_checks()
        check_results = []
        checks = [
            {
                "id": 1,
                "description": "Check if the FTP service is running",
                "command": "service vsftpd status",
                "valid_result": "FTP server is running",
                "remediation": "Start the FTP service with the command service vsftpd start"
            },
            {
                "id": 2,
                "description": "Check if iptables is installed",
                "command": "dpkg -s iptables",
                "valid_result": "Status: install ok installed",
                "remediation": "Install iptables package with command apt install iptables"
            },
            {
                "id" :3,
                "description": "Check disk space usage",
                "command": "df / | awk 'NR==2 {if ($5+0 >= 100) print \"Filesystem full\"; else print \"Filesystem not full\";}'",
                "valid_result": "Filesystem not full",
                "remediation": "Free up disk space or expand the disk"
            }
        ]
        for check in tqdm(checks,desc='Analizando: ',ascii=' ░▒▓█'):
            command = check.get('command')
            valid_result = check.get('valid_result')
            output = ssh.execute_command(command)
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
        # Implementar la lógica de comprobación de escalada de privilegios remota
        pass

    def get_results(self):
        return self.results
