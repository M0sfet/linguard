#Author: Daniel Morales
#Version: 1.0

#Import section
import os
import json
import logging


class InvalidStructure(Exception):
    def __init__(self, mensaje):
        self.mensaje = mensaje
        super().__init__(self.mensaje)

class InvalidCommand(Exception):
    def __init__(self, mensaje):
        self.mensaje = mensaje
        super().__init__(self.mensaje)


def check_struct(json_file):
    json_template = {
    "id": int,
    "description": str,
    "command": str,
    "valid_result": str,
    "remediation": str
    } 
    for key, value_type in json_template.items():
        for check in json_file:
            if key not in check.keys():
                raise InvalidStructure(f"Key missing: {key}")
            if not isinstance(check[key], value_type):
                raise InvalidStructure(f"Key '{key}' type mistmatch. Should be {value_type} but is {type(check[key])}")
    return True

def check_security(json_file):
    invalid_commands = (
        'rm -rf /',
        'dd if=/dev/zero of=/dev/sda',
        'mkfs.ext4 /dev/sda1',
        '>:',
        'chmod 777 /etc/shadow',
        'chown root:root /etc/passwd',
        'wget',
        'curl',
        'nc'
        '>: /dev/sda',
        'echo \'data\' > /dev/sda',
        'shutdown',
        'reboot',
        'nmap',
        'bash',
        'gobuster',
        'start',
        'stop'
    )
    for check in json_file:
        command = check['command']
        for invalid_command in invalid_commands:
            if invalid_command in command:
                raise InvalidCommand(f"Unsecure command: {command}")
    return True

class CheckLoader:
    @staticmethod
    def load_checks(file_name):
        try:
            load_message = '[+] Loading check file...'
            print(load_message)
            struct = False
            security = False
            db_path = os.path.join(os.path.dirname(__file__), 'db')
            for file_name in os.listdir(db_path):
                if file_name.endswith('.json'):
                    with open(os.path.join(db_path, file_name), 'r') as file:
                        checks =json.load(file)
            struct = check_struct(checks)
            security = check_security(checks)
            if struct and security :
                return checks
        except FileNotFoundError:
            logging.error("\n[*] ERROR: File not found")
            exit(1)
        except json.JSONDecodeError:
            logging.error("\n[*] ERROR: Can not decode JSON file")
            exit(1)
        except InvalidStructure as e:
            print(f"\n[*] ERROR: JSON file structure is not valid {e.mensaje}")
            exit(1)
        except InvalidCommand as e:
            print(f"\n[*] ERROR: JSON contains unsecure commands {e.mensaje}")
            exit(1)
