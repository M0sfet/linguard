#Author: Daniel Morales
#Version: 1.0

#Import section
import subprocess
import logging
import re
from tqdm import tqdm

class NmapScanner:
    def __init__(self, targets):
        self.targets = targets

    def scan(self):
        results = []
        for target in tqdm(self.targets,desc='Scanning hosts',ascii=' ░▒▓█'):
            scan_result = self.run_nmap(target)
            results.append({
                    'ip': target,
                    'ports': scan_result,       
            })
        return results

    def run_nmap(self, ip):
        try:
            result = subprocess.run(['nmap', '-Pn', '-T4', '-F', '-sV', ip], capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Error nmap scan on host {ip}: {result.stderr}")
                return []
            return self.parse_nmap_output(result.stdout)
        except Exception as e:
            logging.error(f"Unhandled exception during the scan of host {ip}: {e}")
            exit(1)


    def parse_nmap_output(self, output):
        ports = []
        lines = output.split('\n')
        for line in lines:
            match = re.match(r'(\d+)/tcp\s+open\s+([^\s]+)\s+(.*)', line)
            if match:
                port = int(match.group(1))
                service = match.group(2)
                version = match.group(3)
                ports.append({
                    'port': port,
                    'service': service,
                    'version': version
                })
        return ports

