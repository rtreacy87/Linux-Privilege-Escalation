#!/usr/bin/env python3
"""
Python Version Finder - SSH-based System Enumeration
Finds all versions of Python installed on a target Linux system.
Hardcoded credentials for target: 10.129.205.110
"""

import paramiko
import re
from typing import Set, Dict, List, Tuple

class PythonFinder:
    def __init__(self, host: str, username: str, password: str):
        """Initialize SSH client with hardcoded credentials."""
        self.host = host
        self.username = username
        self.password = password
        self.client = None
        self.python_versions: Dict[str, str] = {}  # path -> version
        
    def connect(self) -> bool:
        """Establish SSH connection to target."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.host, username=self.username, password=self.password)
            print(f"[+] Connected to {self.host} as {self.username}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def exec_command(self, cmd: str) -> str:
        """Execute command on target and return stdout."""
        try:
            stdin, stdout, stderr = self.client.exec_command(cmd)
            return stdout.read().decode('utf-8', errors='ignore').strip()
        except Exception as e:
            print(f"[-] Command execution failed: {cmd} - {e}")
            return ""
    
    def find_python_in_path(self) -> None:
        """Use 'which' to find all python executables in PATH."""
        print("\n[*] Searching PATH for python executables...")
        cmd = "which -a python python2 python2.6 python2.7 python3 python3.6 python3.7 python3.8 python3.9 python3.10 python3.11 python3.12 2>/dev/null"
        output = self.exec_command(cmd)
        if output:
            for line in output.split('\n'):
                if line:
                    self._add_python_version(line)
    
    def find_python_common_locations(self) -> None:
        """Check common Python installation locations."""
        print("\n[*] Checking common Python installation locations...")
        common_paths = [
            "/usr/bin/python*",
            "/usr/local/bin/python*",
            "/opt/python*/bin/python",
            "/opt/*/bin/python",
        ]
        
        for pattern in common_paths:
            cmd = f"find {pattern.split('*')[0]} -maxdepth 2 -type f -name 'python*' 2>/dev/null"
            output = self.exec_command(cmd)
            if output:
                for line in output.split('\n'):
                    if line and 'bin/python' in line:
                        self._add_python_version(line)
    
    def find_python_with_find(self) -> None:
        """Use 'find' command for broader search."""
        print("\n[*] Searching with find command...")
        # Search in standard locations only (faster and less noisy)
        search_paths = ["/usr/bin", "/usr/local/bin", "/opt", "/home"]
        for path in search_paths:
            cmd = f"find {path} -maxdepth 3 -type f -name 'python*' -executable 2>/dev/null"
            output = self.exec_command(cmd)
            if output:
                for line in output.split('\n'):
                    if line and ('python' in line):
                        self._add_python_version(line)
    
    def find_python_via_symlinks(self) -> None:
        """Check for python symlinks in /usr/bin."""
        print("\n[*] Checking for python symlinks and binaries...")
        cmd = "ls -la /usr/bin/python* 2>/dev/null"
        output = self.exec_command(cmd)
        if output:
            for line in output.split('\n'):
                if line:
                    print(f"    {line}")
                    # Extract the path from ls output
                    parts = line.split()
                    if len(parts) >= 9:
                        # Check if it's a symlink
                        if '->' in line:
                            # It's a symlink, parse carefully
                            arrow_idx = line.index('->')
                            target = line[arrow_idx+2:].strip()
                            if not target.startswith('/'):
                                target = '/usr/bin/' + target
                            self._add_python_version(target)
                        else:
                            # It's a regular file, use /usr/bin/ prefix
                            filename = parts[-1]
                            path = '/usr/bin/' + filename
                            self._add_python_version(path)
        
        # Also explicitly check for python3.11 which might not be symlinked
        cmd_311 = "/usr/bin/python3.11 --version 2>&1"
        version_311 = self.exec_command(cmd_311)
        if version_311 and 'Python' in version_311 and 'Permission denied' not in version_311 and 'not found' not in version_311:
            if '/usr/bin/python3.11' not in self.python_versions:
                self.python_versions['/usr/bin/python3.11'] = version_311
                print(f"    [+] /usr/bin/python3.11: {version_311}")
    
    def find_python_via_dpkg(self) -> None:
        """Search for python packages via apt on Debian-based systems."""
        print("\n[*] Searching installed packages for python...")
        cmd = "apt list --installed 2>/dev/null | grep -i python | cut -d'/' -f1"
        output = self.exec_command(cmd)
        if output:
            print("[+] Installed Python packages:")
            for line in output.split('\n'):
                if line:
                    print(f"    {line}")
    
    def find_python_via_whereis(self) -> None:
        """Use 'whereis' command to locate python."""
        print("\n[*] Using 'whereis' to locate python...")
        cmd = "whereis python python2 python3 python2.7 python3.6 python3.7 python3.8 python3.9 python3.10 python3.11 python3.12"
        output = self.exec_command(cmd)
        if output:
            print(f"    {output}")
            # Parse whereis output and add versions
            for item in output.split('\n'):
                if item:
                    parts = item.split()
                    for part in parts[1:]:  # Skip the command name
                        if part and not part.endswith(':'):
                            self._add_python_version(part)
    
    def _add_python_version(self, path: str) -> None:
        """Get version for a Python executable and add to results."""
        if not path or path in self.python_versions:
            return
        
        # Skip if path contains certain patterns (libraries, config files, dirs, etc.)
        skip_patterns = ['.config', '.desktop', '.so', '.a', '-config', '.gz', '.1', 
                         '/lib/python', '/etc/python', '/share/python', '/local/lib/python']
        if any(x in path for x in skip_patterns):
            return
        
        # Get the version
        cmd = f"{path} --version 2>&1"
        version_output = self.exec_command(cmd)
        
        # Only record if we got a valid Python version output
        if version_output and ('Python' in version_output or 'python' in version_output.lower()) and 'Permission denied' not in version_output and 'not found' not in version_output:
            self.python_versions[path] = version_output
            print(f"    [+] {path}: {version_output}")
    
    def display_results(self) -> None:
        """Display all found Python versions."""
        print("\n" + "="*70)
        print("PYTHON VERSION ENUMERATION RESULTS")
        print("="*70)
        
        if not self.python_versions:
            print("[-] No Python installations found")
            return
        
        print(f"\n[+] Found {len(self.python_versions)} Python installation(s):\n")
        
        # Sort by version for better presentation
        sorted_pythons = sorted(self.python_versions.items())
        for path, version in sorted_pythons:
            print(f"  Path:    {path}")
            print(f"  Version: {version}")
            print()
        
        # Extract and display unique versions
        print("\nUnique Python versions found:")
        versions = set()
        for version_str in self.python_versions.values():
            # Extract version number
            match = re.search(r'Python (\d+\.\d+\.\d+|\d+\.\d+)', version_str)
            if match:
                versions.add(match.group(1))
        
        for v in sorted(versions):
            print(f"  - Python {v}")
    
    def close(self) -> None:
        """Close SSH connection."""
        if self.client:
            self.client.close()
            print("\n[+] SSH connection closed")


def main():
    # Hardcoded credentials
    HOST = "10.129.205.110"
    USERNAME = "htb-student"
    PASSWORD = "HTB_@cademy_stdnt!"
    
    finder = PythonFinder(HOST, USERNAME, PASSWORD)
    
    try:
        if not finder.connect():
            return
        
        # Run all enumeration techniques
        finder.find_python_in_path()
        finder.find_python_via_symlinks()
        finder.find_python_with_find()
        finder.find_python_common_locations()
        finder.find_python_via_whereis()
        finder.find_python_via_dpkg()
        
        # Display results
        finder.display_results()
        
    finally:
        finder.close()


if __name__ == "__main__":
    main()
