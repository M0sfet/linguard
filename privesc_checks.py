#Author: Daniel Morales
#Version: 1.0

class PrivesChecks:
    def __init__(self):
        self.checks=[
            {'id': 'sudo_check',
             'command' : 'cat /etc/sudoers',
             'description': 'Review sudo configuration',
             'remediation': 'Delete NOPASSWD configuration in sudoers file'
            },
            {'id': 'setuid_check',
             'command' : 'find / -perm -4000 -type f 2>/dev/null',
             'description': 'Find files with setuid enabled',
             'remediation': 'Review and disable the unmnecesary setuid rights over the files'
            },
            {'id': 'kernel_check',
             'command' : 'uname -r',
             'description': 'Check kernel version',
             'remediation': 'Upgrade kernel version to a not vulnerable version'
            }
        ]
   
    def get_checks(self):
        return self.checks
    