---

title: Linux Logging for SOC

date: 2026-07-28 11:00 +0300

categories: [Foundations, Linux]

tags: [linux, auditd, syslog, ssh, log-analysis]

description: "How Linux logs authentication, user management, package installs, and command history in plain text, why none of that catches runtime activity on its own, and how auditd fills the gap with kernel-level system call monitoring."

---

## Description

"Linux Logging for SOC" builds the same foundation for Linux that the Windows Logging for SOC room built for Windows: knowing which logs exist, where they live, and what a real investigation looks like before touching a SIEM. The room walks through plain-text log basics, the authentication log that carries most of a Linux investigation's weight, the rest of `/var/log`, Bash history and its limits, and finally the runtime monitoring gap that only a tool like auditd can close.

The final task hands over a live VM and a real scenario: a threat actor accessed a sensitive file, pulled a tool down from GitHub, and used it to scan an internal network. Every answer and finding below matches what I confirmed on the platform.

## The problem

Linux runs most of the world's servers and, by Trend Micro's estimate, roughly 90 percent of public cloud workloads. The belief that Linux does not get infected is common and wrong. Ransomware groups now build Linux-specific payloads for VMware ESXi hosts, cryptominers target misconfigured cloud instances, and web shells remain one of the most common ways attackers keep a foothold on a compromised Linux web server. A SOC analyst who only knows Windows logging is blind to most of the infrastructure a modern company runs on.

Linux handles logging differently enough from Windows that the skills do not transfer automatically. There is no Event Viewer, no binary log format, and no numbered event codes. Everything lands in `/var/log` as plain text, which means any text editor or `grep` can read it, but it also means there is no fixed schema to search against. Different distributions, different installed packages, and different admin choices all change what gets logged and how. Finding an answer often comes down to knowing which keyword to grep for rather than which event ID to filter on.

The bigger gap sits underneath all of that. By default, Linux does not log process creation, file changes, or network connections, the category of activity collectively called runtime events. This is the exact same blind spot Windows has without Sysmon. Every meaningful action a program takes on a Linux system, opening a file, spawning a process, reaching out over the network, happens through a system call, one of roughly 300 defined interfaces between a program and the kernel. A tool that watches system calls sees everything. A tool that only reads `/var/log` sees whatever the running services happened to write down. The room builds toward this point: static text logs get an investigation started, but auditd is what finishes it.

## How it works

**Step 1: Read and filter plain text logs.** Task 2 works entirely against `/var/log/syslog`, the aggregated stream most Linux distributions use for general system events.

| Question | How it was found | Answer |
|---|---|---|
| Time server domain the VM synced with | `grep -i ntp /var/log/syslog` | `ntp.ubuntu.com` |
| Kernel message from Yama | `grep -i yama /var/log/syslog` | `Becoming mindful.` |

The workflow here is the same regardless of what you are hunting: pipe the log through `grep`, narrow with a keyword, and read the result. `cat /var/log/syslog | grep CRON` isolates cronjob activity, `grep -v CRON` does the reverse, and `grep -R -E "auth|login|session" /var/log` searches every file in the folder at once when you do not yet know which log holds what you need. That last pattern matters more than it looks. Without event IDs to filter on, discovering the right log file is often the first step of a Linux investigation, not something you can assume going in.

**Step 2: Mine the authentication log.** Task 3 moves to `/var/log/auth.log` (`/var/log/secure` on RHEL-based systems), the single most useful file for a Linux SOC investigation despite its name suggesting a narrower scope than it covers.

| Event type | What to grep for | Notes |
|---|---|---|
| Local and remote logins/logoffs | `session opened` / `session closed` | Covers `login`, `sshd`, `smbd`, `cron`, and `sudo` sessions alike |
| SSH-specific attempts | `Accepted` / `Failed` on `sshd` lines | Format: `<result> <auth-method> for <user> from <ip>` |
| User management | `useradd`, `usermod`, `userdel`, `passwd` | Reveals account creation, group changes, and password resets |
| Commands run via sudo | `COMMAND=` | Shows what a user executed with elevated privileges |

| Question | Answer |
|---|---|
| IP address that failed to log in on multiple users via SSH | `10.14.94.82` |
| User created and added to the `sudo` group | `xerxes` |

A single IP failing SSH logins against more than one username is the signature of a credential-stuffing or password-spray attempt rather than someone fumbling their own login, and MITRE tracks the technique as Brute Force (T1110) feeding into Valid Accounts (T1078) once a guess lands. The follow-up, a new account added straight into the `sudo` group, is Create Account: Local Account (T1136.001): on Linux this runs through `useradd` rather than Windows's `net user /add`, but the intent is identical, secondary credentialed access that does not depend on any remote access tool staying installed. Elastic's detection rules treat this pattern, a fresh account plus an immediate privilege escalation, as a top-priority Linux persistence signal, and MITRE lists this sub-technique as adopted by more than two dozen distinct threat groups and malware families, not just nation-state operators.

The room's own `COMMAND=` example is worth sitting with even outside the graded questions: a user runs sudo to stop an EDR service, checks the firewall rules, then escalates to a root shell with `sudo su`. Disable the watcher, confirm nothing else is watching, take full control. That sequence maps to Impair Defenses (T1562.001) followed directly by privilege escalation, and it is a pattern worth recognizing on sight in a live `auth.log` rather than working it out from scratch during an incident.

**Step 3: Cover the rest of `/var/log`, then learn what Bash history cannot do.** Task 4 rounds out the log inventory: kernel messages (`kern.log`), the general syslog stream, package manager activity (`dpkg.log` on Debian-based systems, `dnf.log` or `yum.log` on RHEL-based ones), and application-specific logs like an Nginx `access.log` that records every web request with its source IP, timestamp, and response code.

| Question | Answer |
|---|---|
| Version of `unzip` installed, per the package manager log | `6.0-28ubuntu4.1` |
| Flag in one user's Bash history | `THM{note_to_remember}` |

Bash history looks like a promising log source since it captures what a user typed, but it fails in three specific ways that matter for detection. A leading space before a command skips it from being recorded at all in a default configuration. Pasting commands into a script and running the script hides every one of those commands from history, since only the script invocation itself gets logged. Switching to a different shell like `sh` means Bash's history mechanism never engages at all. MITRE documents the broader pattern under Clear Command History (T1070.003): once an attacker has a foothold, a typical cleanup sequence looks like `history -c && unset HISTFILE`, sometimes followed by `shred -u ~/.bash_history` to overwrite the file rather than just delete it. None of the three room-listed tricks even require cleanup, since the commands were never written down in the first place.

Defenses exist for some of this. Setting `readonly HISTFILE` in a profile script and marking the history file append-only with `chattr +a ~/.bash_history` both blunt the direct-deletion version of the technique, and forwarding shell history to a centralized log server over syslog keeps a copy an attacker on the local box cannot reach. None of those defenses touch the leading-space trick or the alternate-shell trick, though, which is why the room treats Bash history as a nice-to-have rather than a primary log source.

**Step 4: Understand system calls before touching auditd.** Task 5 is conceptual rather than investigative, and it is the hinge the rest of the room turns on.

| Question | Answer |
|---|---|
| System call commonly used to execute a program | `execve` |
| Can a typical program bypass system calls to open a file or spawn a process? | `Nay` |

Every request a program makes to the kernel, opening a file, spawning a process, touching the network, reading the camera, goes through one of roughly 300 defined system calls. This is how the Linux kernel itself is built, and it applies to every program, not just security tools, which means there is effectively no legitimate way for a normal program to skip this layer. That guarantee is what makes system call monitoring so valuable. A file-based log only records what a program's developer chose to write down. A system call monitor records what the program actually did, regardless of what it logs about itself.

**Step 5: Use auditd to catch what static logs miss.** Task 6 is the room's main investigation, run against live auditd logs on the VM using the `ausearch` command rather than reading `/var/log/audit/audit.log` directly.

| Field in an `ausearch` result | What it means |
|---|---|
| `pid` / `ppid` | Process ID and Parent Process ID, used to build a process tree |
| `auid` | Audit user: the account originally used to log in, even after switching users |
| `uid` | The account that actually ran the command, which can differ from `auid` after `sudo` or `su` |
| `tty` | Session identifier, useful when multiple people share one server |
| `exe` | Absolute path to the executed binary |
| `key` | An optional tag defined in the auditd rule, used to filter related events quickly |

| Question | How it was found | Answer |
|---|---|---|
| When was `secret.thm` first opened | `ausearch -i -k file_thmsecret` | `08/13/25 18:36:54` |
| Original filename downloaded via wget | `ausearch -i -k proc_wget` | `naabu_2.3.5_linux_amd64.zip` |
| Network range scanned with the downloaded tool | `ausearch -i` filtered on the tool's activity | `192.168.50.0/24` |

The tool behind those last two answers is real and worth naming: naabu is an open-source port scanner built by ProjectDiscovery, widely used by bug bounty hunters and penetration testers for fast SYN and CONNECT scans across a target range. Nothing about `naabu_2.3.5_linux_amd64.zip` is inherently malicious, it is a legitimate release binary pulled straight from GitHub, which is why this scenario is realistic. CrowdStrike's 2025 Global Threat Report found that 79 percent of Linux attacks involve no malware at all; attackers log in with valid or stolen credentials and then operate entirely with tools already on the box or trivially available from GitHub, `bash`, `cron`, `curl`, `wget`, and increasingly legitimate pentesting utilities like this one. A hash-based or signature-based detection tool has nothing to flag here, since the file itself is clean. Only process, command-line, and network telemetry, the exact fields auditd captures, can tell the difference between a security researcher running naabu against their own assets and an attacker running the same binary against `192.168.50.0/24` after breaching a host.

Auditd's structural advantage over every other log source in this room is where that telemetry comes from. It operates as a kernel-level framework: audit records get written to a kernel ring buffer before they ever reach disk, which is why a process running as root, even root gained through a fresh `sudo` session, cannot edit them the way it can edit `/var/log/auth.log` or `~/.bash_history`. Clearing Bash history hides typed commands. It does nothing to the `execve` records auditd already captured for the same commands. That gap between what a user can erase and what the kernel already logged is the entire reason SOC teams treat auditd, not Bash history, as the trustworthy record of what happened on a Linux host.

## Why it matters

The room's own closing framing gets this right: Linux logging is chaotic compared to Windows, but it usually holds enough detail to catch the threat if you know where to look. This investigation adds scale to that claim. Elastic's 2025 Global Threat Report found that 89 percent of all logged Linux endpoint behavior across its customer base was brute-force login activity, which lines up with what Task 3 asks you to find, and the same report notes that Linux endpoint detection coverage lags badly behind Windows workstation coverage at most organizations. That combination, heavy attacker interest plus thinner defensive tooling, is what makes `/var/log` fluency a real differentiator rather than a box-ticking exercise.

The naabu scenario in Task 6 is the clearest argument in the whole room for why auditd earns its place above `auth.log`, package logs, and Bash history. An attacker who never drops custom malware, who logs in with a stolen credential and downloads a legitimate open-source tool from GitHub, leaves almost nothing for antivirus or file-reputation tools to catch. They leave a process tree, a set of command-line arguments, and a network connection, and auditd is the only log source in this entire room built to capture all three regardless of what the attacker's tools choose to report about themselves.

The parallel to Windows Logging for SOC is direct. Security log event IDs and Sysmon on Windows map to `auth.log` and auditd on Linux: two different implementations of the same idea, a baseline log for identity and access, and a syscall-level layer underneath it for the runtime activity that baseline log cannot see. An analyst who understands why that second layer exists on one OS carries the reasoning straight into the other, well before learning tool-specific syntax like `ausearch` keys versus Sysmon event IDs.

## Key takeaways

- Linux logging has no event IDs or fixed schema, so investigations often start with discovering the right log file through keyword grepping across `/var/log` rather than filtering a known field.
- `/var/log/auth.log` carries far more than its name suggests: logins, sudo sessions, user management, and every command run with elevated privileges.
- Bash history fails against three trivial evasion tricks, a leading space, a wrapped script, or a different shell, none of which require any cleanup after the fact.
- System calls are the one layer a normal program cannot bypass, which is why tools that monitor them, like auditd, catch activity that file-based logs miss entirely.
- A clean, legitimate tool like naabu defeats signature-based detection outright; only process and command-line visibility separates a researcher's scan from an attacker's.
- Auditd writes to a kernel-level buffer before disk, so it survives the same account-level tampering, like clearing Bash history, that erases evidence from every other log in this room.