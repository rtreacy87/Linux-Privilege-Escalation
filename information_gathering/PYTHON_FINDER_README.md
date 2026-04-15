# Python Finder Script

## Overview
`python_finder.py` is an SSH-based system enumeration tool that automatically discovers all Python versions installed on a target Linux system.

## Features
- **Multiple Enumeration Methods** - Uses `which`, `whereis`, `find`, `ls`, and package manager queries to find Python installations
- **Version Detection** - Automatically retrieves version information for each Python binary found
- **Hardcoded Credentials** - Preconfigured with target credentials for easy execution
- **Filtered Results** - Intelligently filters out library directories, config files, and non-executable entries
- **Summary Output** - Displays all discovered Python installations with their paths and versions

## Target Configuration
- **Host**: 10.129.205.110
- **Username**: htb-student
- **Password**: HTB_@cademy_stdnt!

## Usage

### Prerequisites
```bash
# Ensure Paramiko SSH library is installed
pip install paramiko
```

### Execution
```bash
python3 python_finder.py
```

### Output Example
```
[+] Connected to 10.129.205.110 as htb-student

[*] Searching PATH for python executables...
    [+] /usr/bin/python3: Python 3.8.10
    [+] /usr/bin/python3.11: Python 3.11.3

[*] Checking for python symlinks and binaries...
    [+] /bin/python3: Python 3.8.10

[*] Searching installed packages for python...
[+] Installed Python packages:
    python3.8
    python3.11
    python3.8-minimal
    python3.11-minimal
    ...

======================================================================
PYTHON VERSION ENUMERATION RESULTS
======================================================================

[+] Found 5 Python installation(s):

  Path:    /usr/bin/python3
  Version: Python 3.8.10

  Path:    /usr/bin/python3.11
  Version: Python 3.11.3

Unique Python versions found:
  - Python 3.11.3
  - Python 3.8.10
```

## Enumeration Methods

### 1. PATH Search (`which`)
Uses `which -a` to find all python executables in the system PATH. Fast and reliable for commonly used binaries.

### 2. Symlink and Binary Check
Directly lists `/usr/bin/python*` files to catch binaries not in PATH. Includes explicit fallback for python3.11.

### 3. Find Command
Recursively searches standard directories (`/usr/bin`, `/usr/local/bin`, `/opt`, `/home`) for Python executables.

### 4. Common Locations
Checks known Python installation directories like `/usr/local/bin` and `/opt`.

### 5. Whereis Command
Uses `whereis` to locate binaries across the entire system (supports library directories but filters them out).

### 6. Package Manager Query
Lists Python-related packages installed via `apt` to show all Python versions managed by the system.

## Enumeration Techniques Reference

Based on the Linux Services and Internals Enumeration guide:

- **Binaries Search**: Compares `/bin`, `/usr/bin/`, `/usr/sbin/` directories
- **Package Enumeration**: Uses `apt list --installed` on Debian-based systems
- **Version Checking**: Executes binaries with `--version` flag to extract version information
- **Tool Discovery**: Identifies installed tools that may have security implications (e.g., Python versions used by services)

## Implementation Notes

### Filtering Logic
The script intelligently filters out false positives:
- Directories (`/lib/python`, `/etc/python`, `/usr/share/python`)
- Config files (`.config`, `.desktop`)
- Manual pages (`.1.gz`)
- Shared libraries (`.so`, `.a`)

### Error Handling
- Skips entries with "Permission denied" errors
- Ignores "not found" or missing binaries
- Handles SSH connection failures gracefully
- Deduplicates results across multiple search methods

### Security Consideration
The script hardcodes credentials for convenience in testing environments. For production use, consider:
- Using SSH key authentication
- Reading credentials from environment variables
- Implementing credential prompting

## Output Interpretation

The script identifies:
1. **Python executables** - Direct paths to Python interpreters
2. **Version information** - The exact Python version (e.g., 3.8.10, 3.11.3)
3. **Installation paths** - Where Python is installed on the system
4. **Installed packages** - System-managed Python packages and modules

This information is useful for:
- Identifying outdated Python versions with known CVEs
- Checking for multiple Python installations to find version-specific vulnerabilities
- Assessing Python-dependent services for exploitation potential
- Planning privilege escalation via Python-based scripts or libraries

## Troubleshooting

### No Python versions found
- Verify SSH credentials are correct
- Check if Python is actually installed on the target
- Ensure SSH access is working: `ssh htb-student@10.129.205.110`

### Connection refused
- Verify target IP and port
- Confirm SSH service is running on target
- Check firewall rules

### Permission denied errors
- These are normal when checking library directories
- The script filters these out automatically
- Indicates attempted checks into system directories (expected behavior)
