#Author: Daniel Morales
#Version: 1.0

#Import section
import requests
import logging
from os import path


class OsintCheck:
    @staticmethod
    def check_kernel_exploits(version):
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
                return 'vulnerable', exploits
            else:
                return 'not vulnerable', 'No known privilege escalation exploits found'
        
        except requests.RequestException as e:
            logging.error(f"Error checking exploits for kernel version {version}: {e}")
            return 'fail', 'Error checking exploits'
    
    @staticmethod
    def check_gtfobins_exploits(file):
        url = f" https://gtfobins.github.io/gtfobins/{path.basename(file)}" 
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return url
            else:
                return 'not_found'
        except requests.RequestException as e:
            logging.error(f"Error checking GTFObins for binary {file}: {e}")
            return 'fail'