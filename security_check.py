#Author: Daniel Morales
#Version: 1.0

#Import section
import threading
from nmap_scanner import NmapScanner
from ssh_connector import SSHConnector
from check_loader import CheckLoader

class RemoteCheck:
    def __init__(self, path, check_type):
        self.path = path
        self.check_type = check_type
        self.targets = self.load_targets()
        self.results = []

    def load_targets(self):
        with open(self.path, 'r') as file:
            return json.load(file)

    def run_checks(self):
        reachable_hosts = self.scan_hosts()
        threads = []
        for host in reachable_hosts:
            if len(threads) >= 3:
                threads[0].join()
                threads.pop(0)
            thread = threading.Thread(target=self.run_checks_on_host, args=(host,))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()

    def scan_hosts(self):
        nmap_scanner = NmapScanner(self.targets)
        return nmap_scanner.scan()

    def run_checks_on_host(self, host):
        ssh = SSHConnector(host['ip'], host['username'], host['password'])
        if self.check_type == 'config':
            self.run_config_checks(ssh)
        elif self.check_type == 'privilege':
            self.run_privilege_checks(ssh)

    def run_config_checks(self, ssh):
        checks = CheckLoader.load_checks()
        for check in checks:
            command = check.get('command')
            valid_result = check.get('valid_result')
            stdout, stderr = ssh.execute_command(command)
            result = 'pass' if valid_result in stdout else 'fail'
            self.results.append({
                'id': check.get('id'),
                'description': check.get('description'),
                'remediation': check.get('remediation'),
                'result': result
            })


    def run_privilege_checks(self, ssh):
        # Implementar la lógica de comprobación de escalada de privilegios remota
        pass
