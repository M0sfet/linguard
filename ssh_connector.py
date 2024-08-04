#Author: Daniel Morales
#Version: 1.0

#Import section
import logging
import paramiko
import sys


#Class
class SSHConnector:
    def __init__(self, ip, username, password=None, key_path=None):
        self.ip = ip
        self.username = username.lower()
        self.password = password
        self.key_path = key_path
        self.client = self.connect()

    def connect(self):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if self.username == 'root':
                raise ValueError("SSH connection using root user is not allowed")
                sys.exit(1)
            if self.key_path:
                key = paramiko.RSAKey.from_private_key_file(self.key_path)
                client.connect(self.ip, username=self.username, pkey=key)
            else:
                client.connect(self.ip, username=self.username, password=self.password)
            return client
        except paramiko.AuthenticationException:
            logging.error(f"Authentication failure when connecting to host: {self.ip}")
            sys.exit(1)
        except paramiko.SSHException as ssh_connect_error:
            logging.error(f"Connection error to host {self.ip}: {ssh_connect_error}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Unhandled exception: {e}")
            sys.exit(1)


    def execute_command(self, command):
        try:
            if self.password:
                command = f'echo {self.password} | sudo -S {command}'
                stdin, stdout, stderr = self.client.exec_command(command)
                return stdout.read().decode()
            else:
                raise ValueError("User password is required for sudo command execution")
        except paramiko.SSHException as ssh_execute_error:
            logging.error(f"Command execution error of command: '{command}' in host {self.ip}: {ssh_execute_error}")
            
        except Exception as e:
            logging.error(f"Unhandled exception: {e}")
     
    def close(self):
        self.client.close()
