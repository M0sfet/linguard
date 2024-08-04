#Author: Daniel Morales
#Version: 1.0

#Import section
import subprocess

class NmapScanner:
    def __init__(self, targets):
        self.targets = targets

    def scan(self):
        reachable_hosts = []
        for target in self.targets:
            result = subprocess.run(['nmap', '-p', '22', target['ip']], capture_output=True, text=True)
            if '22/tcp open' in result.stdout:
                reachable_hosts.append(target)
        return reachable_hosts
