import os
import pwd
import grp
import psutil
import subprocess
import platform
import re
from datetime import datetime

TOOL_INTRO = """
   _____                ___          ____       _       _ __                   ______                __      __  _           
  / ___/__  _____  ____/ ( )_____   / __ \\_____(_)   __(_) /__  ____ ____     / ____/_____________ _/ /___ _/ /_(_)___  ____ 
  \\__ \\/ / / / _ \\/ __  /|// ___/  / /_/ / ___/ / | / / / / _ \\/ __ `/ _ \\   / __/ / ___/ ___/ __ `/ / __ `/ __/ / __ \\/ __ \\
 ___/ / /_/ /  __/ /_/ /  (__  )  / ____/ /  / /| |/ / / /  __/ /_/ /  __/  / /___(__  ) /__/ /_/ / / /_/ / /_/ / /_/ / / / /
/____/\\__, /\\___/\\__,_/  /____/  /_/   /_/  /_/ |___/_/_/\\___/\\__, /\\___/  /_____/____/\\___/\\__,_/_/\\__,_/\\__/_/\\____/_/ /_/ 
    _/____/    __            __  _                ______     /____/ __                                                       
   / __ \\___  / /____  _____/ /_(_)___  ____     /_  __/___  ____  / /                                                       
  / / / / _ \\/ __/ _ \\/ ___/ __/ / __ \\/ __ \\     / / / __ \\/ __ \\/ /                                                        
 / /_/ /  __/ /_/  __/ /__/ /_/ / /_/ / / / /    / / / /_/ / /_/ / /                                                         
/_____\\___/\\__\\___/\\___/\\__/_/\\____/_/ /_/ /    /_/  \\____/\\____/_/                                                          
"""

# Developer and Disclaimer Notes
DEVELOPER_NOTE = """
Tool developed and maintained by Syed Salman.
This tool is in beta version.
"""

DISCLAIMER = """
Disclaimer:
This tool is intended for educational and research purposes only. Unauthorized use of this tool to compromise systems or networks is illegal and unethical. Always ensure you have permission before running security tools on any system.
"""

# Function to analyze user privileges
def analyze_user_privileges():
    print("Analyzing user privileges...\n")
    user_id = os.getuid()
    user_name = pwd.getpwuid(user_id).pw_name
    groups = [g.gr_name for g in grp.getgrall() if user_name in g.gr_mem]
    
    print(f"User ID: {user_id}")
    print(f"User Name: {user_name}")
    print(f"Groups: {', '.join(groups)}")

    if user_id == 0:
        print("User has elevated (root) privileges.\n")
    else:
        print("User does not have elevated privileges.\n")

# Function to check file and directory permissions
def check_file_permissions(paths):
    print("Checking file and directory permissions...\n")
    for path in paths:
        try:
            stat_info = os.stat(path)
            permissions = oct(stat_info.st_mode)[-3:]
            print(f"{path}: Permissions - {permissions}")
            if permissions in ['777', '775', '755']:
                print(f"Warning: {path} has insecure permissions.\n")
            else:
                print(f"{path} has secure permissions.\n")
        except Exception as e:
            print(f"Error accessing {path}: {e}")

# Function to analyze running processes
def analyze_processes():
    print("Analyzing running processes...\n")
    for proc in psutil.process_iter(['pid', 'name', 'username', 'uids']):
        try:
            if proc.info['uids'].real == 0:
                print(f"Suspicious Process: {proc.info}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Function to analyze registry entries (Windows only)
def analyze_registry():
    if platform.system() != 'Windows':
        print("Registry analysis is only supported on Windows systems.\n")
        return
    
    print("Analyzing registry entries...\n")
    keys_to_check = [
        r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    ]
    
    for key in keys_to_check:
        try:
            result = subprocess.run(['reg', 'query', key], capture_output=True, text=True, check=True)
            print(f"{key}:\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            print(f"Error querying {key}: {e}")

# Function to analyze system logs
def analyze_logs(log_paths):
    print("Analyzing system logs...\n")
    suspicious_patterns = [
        re.compile(r'authentication failure'),
        re.compile(r'error: PAM:'),
        re.compile(r'sudo: .*: command not found')
    ]

    for log_path in log_paths:
        try:
            with open(log_path, 'r') as log_file:
                for line in log_file:
                    for pattern in suspicious_patterns:
                        if pattern.search(line):
                            print(f"Suspicious log entry in {log_path}: {line.strip()}")
        except Exception as e:
            print(f"Error reading log {log_path}: {e}")

# Instructions for running the tool
def print_instructions():
    instructions = """
    This tool analyzes the current system for potential privilege escalation vulnerabilities.
    
    Functions:
    1. Analyze User Privileges
    2. Check File and Directory Permissions
    3. Analyze Running Processes
    4. Analyze Registry Entries (Windows only)
    5. Analyze System Logs

    Usage:
    1. Ensure you have the necessary permissions to run the script.
    2. Customize the paths and log files to be checked.
    3. Run the script using Python 3.x: $ python3 privil_escal_detection.py
    """
    print(instructions)

if __name__ == "__main__":
    print(TOOL_INTRO)
    print(DEVELOPER_NOTE)
    print(DISCLAIMER)
    print_instructions()
    analyze_user_privileges()
    critical_paths = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
    check_file_permissions(critical_paths)
    analyze_processes()
    analyze_registry()
    log_paths = ['/var/log/faillog', '/var/log/lastlog']
    # log_paths = ['/var/log/auth.log', '/var/log/secure']
    analyze_logs(log_paths)

