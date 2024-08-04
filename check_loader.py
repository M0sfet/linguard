#Author: Daniel Morales
#Version: 1.0

#Import section
import os
import json

class CheckLoader:
    @staticmethod
    def load_checks():
        checks = []
        db_path = os.path.join(os.path.dirname(__file__), 'db')
        for file_name in os.listdir(db_path):
            if file_name.endswith('.json'):
                with open(os.path.join(db_path, file_name), 'r') as file:
                    checks.append(json.load(file))
        return checks