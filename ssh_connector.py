#Author: Daniel Morales
#Version: 1.0

#Import section
import logging
import paramiko



#Class
class SSHConnector:
    def __init__(self, ip, username, key_path, password):
        self.ip = ip
        self.username = username.lower()
        self.password = password
        self.key_path = key_path
        self.client = self.connect()

    def connect(self):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            key = paramiko.RSAKey.from_private_key_file(self.key_path)
            client.connect(self.ip, username=self.username, pkey=key)             
            return client
        except paramiko.AuthenticationException:
            logging.error(f"Authentication failure when connecting to host: {self.ip}\n")
            exit(1)
        except paramiko.SSHException as ssh_connect_error:
            logging.error(f"Connection error to host {self.ip}: {ssh_connect_error}\n")
            exit(1)
        except Exception as e:
            logging.error(f"Unhandled exception: {e}\n")
            exit(1)


    def execute_command(self, command):
        try:
            command = f'echo {self.password} | sudo -S {command}'
            stdin, stdout, stderr = self.client.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                if 'incorrect password attempt' in stderr.read().decode():
                    print("\n[*] ERROR: Contraseña invalida")
                    return "command_exec_error"
                return stderr.read().decode()
            else:
               return stdout.read().decode()
        except paramiko.SSHException as ssh_execute_error:
            logging.error(f"Command execution error of command: '{command}' in host {self.ip}: {ssh_execute_error}\n")
            
        except Exception as e:
            logging.error(f"Unhandled exception: {e}\n")
            return "command_exec_error"

    def get_ip(self):
        return self.ip
     
    def close(self):
        self.client.close()
