#!/usr/bin/env python3
"""
PATH Abuse Finder

Connects to a Linux target over SSH and identifies non-default PATH entries
for a specific user. This is useful for detecting PATH abuse opportunities
in privilege-escalation labs.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set

import paramiko


HOST = "10.129.2.210"
USERNAME = "htb-student"
PASSWORD = "Academy_LLPE!"
PORT = 22

# Common default PATH entries seen in Debian/Ubuntu lab targets.
DEFAULT_PATH_ENTRIES: Set[str] = {
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/usr/games",
    "/usr/local/games",
    "/snap/bin",
}


def split_path(path_value: str) -> List[str]:
    return [entry.strip() for entry in path_value.split(":") if entry.strip()]


def unique_keep_order(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


class PathAbuseFinder:
    def __init__(self, host: str, username: str, password: str, port: int = 22) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=15,
            banner_timeout=15,
            auth_timeout=15,
        )

    def close(self) -> None:
        if self.client:
            self.client.close()

    def run(self, command: str) -> str:
        if not self.client:
            raise RuntimeError("SSH client is not connected")
        _, stdout, _ = self.client.exec_command(command)
        return stdout.read().decode(errors="replace").strip()

    def collect_paths(self) -> Dict[str, str]:
        commands = {
            "direct_env": "echo \"$PATH\"",
            "login_shell": "bash -lc 'echo \"$PATH\"'",
            "interactive_shell": "bash -ic 'echo \"$PATH\"' 2>/dev/null",
            "python_env": "python3 -c 'import os; print(os.environ.get(\"PATH\", \"\"))'",
        }
        return {name: self.run(cmd) for name, cmd in commands.items()}

    def collect_path_files(self) -> Dict[str, str]:
        files = [
            "~/.bashrc",
            "~/.profile",
            "~/.bash_profile",
            "/etc/environment",
            "/etc/profile",
            "/etc/bash.bashrc",
        ]

        file_data: Dict[str, str] = {}
        for file_path in files:
            content = self.run(
                f"if [ -r {file_path} ]; then echo '=== {file_path} ==='; sed -n '1,220p' {file_path}; fi"
            )
            if content:
                file_data[file_path] = content
        return file_data

    @staticmethod
    def extract_path_assignments(text: str) -> List[str]:
        assignments: List[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "PATH=" in line:
                assignments.append(line)
        return assignments


def main() -> None:
    finder = PathAbuseFinder(HOST, USERNAME, PASSWORD, PORT)

    try:
        finder.connect()

        paths = finder.collect_paths()
        print(f"[+] Connected to {HOST} as {USERNAME}")

        all_entries: List[str] = []
        print("\n[+] PATH values by context:")
        for context, value in paths.items():
            print(f"\n[{context}]\n{value}")
            all_entries.extend(split_path(value))

        file_data = finder.collect_path_files()
        print("\n[+] PATH-related assignments in shell/init files:")
        for file_path, content in file_data.items():
            assignments = finder.extract_path_assignments(content)
            if assignments:
                print(f"\n{file_path}")
                for assignment in assignments:
                    print(f"  {assignment}")
                    # Pull literal absolute paths from PATH assignment lines.
                    all_entries.extend(re.findall(r"/[A-Za-z0-9_./-]+", assignment))

        merged = unique_keep_order(all_entries)
        non_default = [entry for entry in merged if entry not in DEFAULT_PATH_ENTRIES]

        print("\n[+] Non-default PATH entries:")
        if non_default:
            for entry in non_default:
                print(f"  - {entry}")
            print(f"\n[ANSWER] {non_default[0]}")
        else:
            print("  (none found)")
            print("\n[ANSWER] No non-default PATH directory found.")

    except Exception as exc:
        print(f"[-] Error: {exc}")
    finally:
        finder.close()


if __name__ == "__main__":
    main()
