# Local Privilege Escalation Detection Tool

   _____                ___          ____       _       _ __                   ______                __      __  _           
  / ___/__  _____  ____/ ( )_____   / __ \\_____(_)   __(_) /__  ____ ____     / ____/_____________ _/ /___ _/ /_(_)___  ____ 
  \\__ \\/ / / / _ \\/ __  /|// ___/  / /_/ / ___/ / | / / / / _ \\/ __ `/ _ \\   / __/ / ___/ ___/ __ `/ / __ `/ __/ / __ \\/ __ \\
 ___/ / /_/ /  __/ /_/ /  (__  )  / ____/ /  / /| |/ / / /  __/ /_/ /  __/  / /___(__  ) /__/ /_/ / / /_/ / /_/ / /_/ / / / /
/____/\\__, /\\___/\\__,_/  /____/  /_/   /_/  /_/ |___/_/_/\\___/\\__, /\\___/  /_____/____/\\___/\\__,_/_/\\__,_/_\\__/_\\____/_/ /_/ 
    _/____/    __            __  _                ______     /____/ __                                                       
   / __ \\___  / /____  _____/ /_(_)___  ____     /_  __/___  ____  / /                                                       
  / / / / _ \\/ __/ _ \\/ ___/ __/ / __ \\/ __ \\     / / / __ \\/ __ \\/ /                                                        
 / /_/ /  __/ /_/  __/ /__/ /_/ / /_/ / / / /    / / / /_/ / /_/ / /                                                         
/_____\\___/\\__\\___/\\___/\\__/_/\\____/_/ /_/    /_/  \\____/\\____/_/                                                          

## Overview

The Local Privilege Escalation Detection Tool is a Python-based script designed to detect potential privilege escalation vulnerabilities on a system. The tool performs various checks including:

1. **User Privilege Analysis**: Analyzes the current user's privileges to determine if any elevated privileges are present.
2. **File and Directory Permissions**: Scans critical system files and directories to check for incorrect or insecure permissions.
3. **Process Analysis**: Monitors running processes and identifies any suspicious or unauthorized processes with elevated privileges.
4. **Registry Analysis**: Checks the system registry for unauthorized or modified entries related to user privileges (Windows only).
5. **Log Analysis**: Analyzes system logs for any suspicious activities or indicators of privilege escalation attempts.


## Features

- **User Privilege Analysis**: Detects if the current user has elevated (root) privileges.
- **File and Directory Permissions**: Checks for insecure permissions on critical files and directories.
- **Process Analysis**: Identifies suspicious processes running with elevated privileges.
- **Registry Analysis**: Analyzes critical registry entries for signs of unauthorized modifications (Windows only).
- **Log Analysis**: Scans system logs for indicators of privilege escalation attempts.

## Usage Instructions

1. **Ensure you have the necessary permissions to run the script**: Running this tool might require administrative privileges.
2. **Customize the paths and log files to be checked**: Modify the `critical_paths` and `log_paths` lists in the script to include the files and directories specific to your environment.
3. **Run the script using Python 3.x**:
   ```py
   $ python3 privilege_escalation_detection.py
   ```

## System Requirements

- **Operating System**: `Linux or Windows`
- **Python Version**: `Python 3.x`
- **Dependencies**: `psutil`,`pwd`,`grp`,`subprocess`,`platform`,`re`

## Developer and Disclaimer Notes

**Developer Note**:

Tool developed and maintained by `Salmanfareeth`.
This tool is in beta version.

**Disclaimer**:

This tool is intended for educational and research purposes only. Unauthorized use of this tool to compromise systems or networks is illegal and unethical. Always ensure you have permission before running security tools on any system.
  
