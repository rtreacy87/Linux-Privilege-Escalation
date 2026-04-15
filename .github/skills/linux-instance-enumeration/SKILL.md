---
name: linux-instance-enumeration
description: 'Enumerate a Linux host for privilege escalation, service discovery, version checking, credential hunting, and flag discovery. Use when assessing Linux instances, comparing exact package or interpreter versions against CVEs, deciding whether linpeas is warranted, or reviewing services, internals, web roots, cron jobs, sudo rights, and accessible secrets.'
argument-hint: 'Target host, current access level, and goal such as versions, creds, or privesc'
user-invocable: true
disable-model-invocation: false
---

# Linux Instance Enumeration

## What This Skill Does

This skill provides a repeatable Linux enumeration workflow focused on:

- System identity and exact version collection
- User, group, sudo, and shell context
- Services, sockets, timers, and cron jobs
- Credential hunting in configs, histories, backups, and web roots
- Tooling and interpreter discovery for exploitability checks
- Deciding when linpeas adds value and when it is overkill

It is based on these repo notes:

- `linux_privilege_escalation/information_gathering_environment_enumeration.md`
- `linux_privilege_escalation/information_gathering_linux_services_and_internals_enumeration.md`
- `linux_privilege_escalation/information_gathering_credential_hunting.md`

If local Python tooling is needed to run helper scripts, install packages, or check package versions, use the operator virtual environment at `~/htb/venv`.

## When To Use

Use this skill when:

- You have shell access to a Linux host and need a structured enumeration pass
- You need exact versions for CVE triage rather than rough package family names
- You are assessing local privilege escalation paths
- You need to hunt for credentials such as WordPress database passwords or SSH keys
- You need to decide whether to run linpeas or stay with targeted manual checks

## Local Tooling Constraint

When running Python locally from the operator machine:

- Prefer `~/htb/venv/bin/python` over system Python
- Prefer `~/htb/venv/bin/pip` for any package installs or version checks
- If you need to verify a local package version before running a helper script, query it from `~/htb/venv`

Examples:

- `~/htb/venv/bin/python --version`
- `~/htb/venv/bin/python -m pip show paramiko`
- `~/htb/venv/bin/python -c "import pkg; print(pkg.__version__)"`

## Manual Enumeration Order

1. Establish context first.

- `whoami`
- `id`
- `hostname`
- `env | sort`
- `echo $PATH`
- `pwd`

2. Capture exact platform and version data.

- `cat /etc/os-release`
- `uname -a`
- `hostnamectl`
- `lscpu`
- `lsblk`
- `mount`
- `cat /etc/fstab`

3. Capture exact package and interpreter versions relevant to CVEs.

- `sudo -V`
- `python3 --version`
- `ls -l /usr/bin/python* /usr/local/bin/python* 2>/dev/null`
- `dpkg-query -W -f='${binary:Package}\t${Version}\n' 'python*' 'libpython*' 2>/dev/null | sort`
- `apt list --installed 2>/dev/null`
- `snap list 2>/dev/null`
- `lxc --version 2>/dev/null`
- `systemctl --version`
- `bash --version | head -n 1`
- `openssl version -a`
- `dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null | sort`

4. Enumerate users, groups, and access.

- `cat /etc/passwd`
- `grep 'sh$' /etc/passwd`
- `cat /etc/group`
- `sudo -l`
- `lastlog`
- `w`
- `history`
- `find / -type f \( -name "*_hist" -o -name "*_history" -o -name ".bash_history" \) -ls 2>/dev/null`

5. Enumerate services, internals, and scheduled execution.

- `systemctl list-units --type=service --state=running --no-pager`
- `systemctl list-timers --all --no-pager`
- `ss -lntup`
- `ip a`
- `route`
- `arp -a`
- `cat /etc/hosts`
- `ls -lah /etc/cron*`
- `find /etc/cron* /var/spool/cron -maxdepth 2 -type f -readable -exec ls -lah {} \; 2>/dev/null`

6. Hunt credentials and app secrets deliberately.

- `find /home /var/www /opt /srv /etc -type f \( -iname '*.env' -o -iname '*.conf' -o -iname '*.config' -o -iname '*.xml' -o -iname '*.ini' -o -iname '*.yaml' -o -iname '*.yml' -o -iname '*config*' -o -iname '*.bak' -o -iname '*secret*' -o -iname '*credential*' -o -iname '*id_rsa*' \) -readable 2>/dev/null`
- `grep -RInE '(password|passwd|pwd|secret|token|api[_-]?key|DB_PASSWORD|DB_USER|DB_NAME)' /home /var/www /opt /srv /etc 2>/dev/null`
- `find / -type f \( -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.rb' \) -readable -exec grep -HnE '(HTB\{|flag\{|password|passwd|pwd|secret|token|api[_-]?key)' {} + 2>/dev/null`
- `find /var/mail /var/spool/mail /var/spool /var/log -type f -readable -exec grep -HnE '(password|passwd|pwd|secret|token|api[_-]?key|DB_PASSWORD|DB_USER|DB_NAME|HTB\{|flag\{)' {} + 2>/dev/null`
- `find /home /var/www /opt /srv -type f \( -iname '*.db' -o -iname '*.sqlite' -o -iname '*.sqlite3' -o -iname '*.sql' -o -iname '*.txt' -o -iname '*.log' \) -readable -exec grep -HnE '(password|passwd|pwd|secret|token|api[_-]?key|DB_PASSWORD|DB_USER|DB_NAME|HTB\{|flag\{)' {} + 2>/dev/null`
- `find /var/www -type f \( -name 'wp-config.php' -o -name '.env' -o -name 'config.php' \) 2>/dev/null`
- `grep -RInE 'DB_(NAME|USER|PASSWORD)|mysqli|pdo|mysql' /var/www 2>/dev/null`
- `ls ~/.ssh 2>/dev/null && cat ~/.ssh/known_hosts 2>/dev/null`
- `find /home /root -type f \( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name 'known_hosts' -o -name 'authorized_keys' \) -readable 2>/dev/null`

7. Record flags and proof files last, but search precisely.

- `find / -type f \( -name 'user.txt' -o -name 'root.txt' -o -name 'flag.txt' \) -readable 2>/dev/null`

## Linpeas Guidance

### Run linpeas when it is justified

Run linpeas after you already have basic host context when:

- The host is a lab, CTF, HTB box, or internal assessment target where broad noisy enumeration is acceptable
- You suspect multiple weak signals and want correlation across sudo, SUID, writable paths, services, capabilities, cron, and groups
- You need a second pass to catch missed local privesc avenues
- You want a fast inventory of common misconfigurations before deeper manual validation

Recommended order:

1. Gather identity, OS, kernel, network, users, and exact version data manually first.
2. Run targeted credential and web-root checks if the objective is secret hunting.
3. Run linpeas once you have enough context to interpret its results instead of treating it as the first and only step.

### Linpeas is overkill when

- You only need one exact version or one specific fact such as Python or sudo version
- You already know the likely path and just need targeted confirmation
- The environment is production-sensitive and noisy broad enumeration is risky or unnecessary
- The host is resource-constrained and exhaustive enumeration may disrupt service or produce too much low-value output
- The task is credential hunting in one app directory and focused greps will answer it faster
- You are building an exact version inventory for CVE comparison and a few direct commands will answer it with less noise

### Practical rule

Use manual enumeration first for exact facts and context. Use linpeas as a broad correlation and gap-finding tool, not as a substitute for understanding the system.

## Exact Version Discipline

If you are checking CVEs, do not stop at package names. Capture:

- Executable path
- Executable `--version` output
- Symlink target
- Package manager version string
- Running process path if relevant

Example for Python:

- `python3 --version`
- `ls -lah /usr/bin/python3`
- `readlink -f /usr/bin/python3`
- `dpkg-query -W -f='${binary:Package}\t${Version}\n' 'python3*' 'libpython3*'`

## WordPress Credential Hunting

For WordPress specifically:

1. Search for `wp-config.php` under `/var/www`, `/srv`, and `/opt`.
2. Extract `DB_NAME`, `DB_USER`, and `DB_PASSWORD`.
3. Note ownership and permissions on the app tree.
4. Cross-check whether the same password appears in shell histories, backups, or reused database credentials.

Useful commands:

- `find /var/www /srv /opt -type f -name 'wp-config.php' 2>/dev/null`
- `grep -nE "DB_(NAME|USER|PASSWORD)" /path/to/wp-config.php`

Common credential locations to prioritize from these notes:

- Web roots under `/var/www`
- Config files such as `.conf`, `.config`, `.xml`, `.ini`, `.yaml`, `.env`
- Backup files such as `.bak`
- User history files such as `.bash_history`
- SSH material in `~/.ssh/`

## Output Expectations

The result of this workflow should answer, at minimum:

- What OS, kernel, and exact package versions are present?
- Which users, groups, and sudo rules matter?
- Which services and scheduled tasks are interesting?
- What credentials or secrets are exposed?
- Are any flags or secrets hardcoded inside readable helper scripts?
- What exact flags or proof files were found?
- Which findings are confirmed by manual evidence versus only suggested by linpeas?