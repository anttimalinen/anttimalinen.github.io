---

title: Linux Threat Detection 2

date: 2026-07-30 13:00 +0300

categories: [Foundations, Linux]

tags: [linux, discovery, auditd, cryptominer, ingress-tool-transfer]

description: "How attackers orient themselves right after breaching a Linux host, how they pull malware onto the box without always tripping the log source you'd expect, and a real cryptominer botnet traced end to end through auditd."

---

## Description

"Linux Threat Detection 2" picks up exactly where Linux Threat Detection 1 left off: the attacker is already inside. This room covers what happens next, Discovery, the commands a threat actor runs to figure out where they landed, and Ingress Tool Transfer, how they get malware onto a box they do not own. The room closes with a full case study of Dota3, a cryptominer botnet that has been hitting exposed SSH servers since before 2020 and is, according to the researchers who track it, still doing so today.

Every answer and finding below matches what I confirmed on the platform.

## The problem

Land on an unfamiliar Linux system with nothing but a command line, and the first questions are always the same: where am I, who am I, what else is running here, is anyone watching. Attackers ask the identical questions, for the identical reason, which is why Discovery (MITRE tactic TA0007) looks almost the same across nearly every intrusion regardless of entry point or goal. The one command in that lineup worth building a detection rule around by itself is `whoami`. Legitimate applications almost never call it. Attackers, whether human or automated, run it first out of habit, which makes it one of the highest signal-to-noise commands a SOC can watch for on a Linux fleet.

Ingress Tool Transfer (T1105), getting a cryptominer, a scanner, or a backdoor onto the compromised host, sounds simpler than it is. `wget`, `curl`, and `scp` are already installed on nearly every Linux server, so the attacker rarely needs to bring their own tools, only a URL or a set of credentials. The complication is directional. If the attacker's own machine reaches out and copies a file onto the victim, that transfer shows up as an SSH login in the victim's `auth.log`, not as a process in auditd, since the `scp` process itself never ran on the victim at all. If the victim's shell is the one pulling the file, the opposite is true: nothing unusual appears in the login logs, but auditd catches the `scp` or `curl` process directly. Knowing which log source to check depends on knowing which side initiated the connection, and getting that backward means looking in the wrong place entirely.

Both problems converge on the room's real subject: a complete, real-world infection chain. Dota3 is not a hypothetical built to teach a concept. It is an active botnet, and walking through its Discovery and Ingress Tool Transfer stages is the same walk a SOC analyst would take against a live alert.

## How it works

**Step 1: Recognize universal Discovery commands.** Task 2 lays out the baseline commands nearly every attacker runs within the first minute of landing on a Linux host, organized by what they are trying to learn.

| Discovery goal | Typical commands |
|---|---|
| OS and filesystem | `pwd`, `ls /`, `env`, `uname -a`, `lsb_release -a`, `hostname` |
| Users and groups | `id`, `whoami`, `w`, `last`, `cat /etc/sudoers`, `cat /etc/passwd` |
| Processes and network | `ps aux`, `top`, `ip a`, `ip r`, `arp -a`, `ss -tnlp`, `netstat -tnlp` |
| Cloud or sandbox detection | `systemd-detect-virt`, `lsmod`, `uptime`, `pgrep <edr-name>` |

| Question | Answer |
|---|---|
| Output of `systemd-detect-virt` | `Amazon` |
| Path to the detected antimalware binary in `ps aux` | `/var/lib/ultrasec/malscan` |

These four categories map cleanly onto established MITRE techniques: System Information Discovery (T1082) and System Owner/User Discovery (T1033) for the first two rows, Process Discovery (T1057) and System Network Configuration Discovery (T1016) for the third, and Virtualization/Sandbox Evasion (T1497) for `systemd-detect-virt`, which tells an attacker whether they landed on real infrastructure or something that might be watching them, like a honeypot or malware sandbox. None of these commands require any special tooling on the attacker's part. They are already sitting on the system, waiting to be run by whoever gets there first.

**Step 2: Use process context to separate attackers from IT staff.** Task 3 moves to more targeted Discovery, credential hunting, mining-suitability checks, and internal network scanning, and introduces the room's central judgment call: the same command can be an attack or routine administration, and only the process tree tells you which.

| Attack objective | Typical commands |
|---|---|
| Steal credentials and secrets | `history \| grep pass`, `find / -name .env`, `find /home -name id_rsa` |
| Assess mining suitability | `cat /proc/cpuinfo`, `lscpu \| grep Model`, `free -m`, `top`, `htop` |
| Scan the internal network | `ping <ip>`, a `for` loop testing port 22 across a subnet with `nc` |

| Question | Answer |
|---|---|
| Path of the script that launched `hostname` | `/home/itsupport/debug.sh` |
| Last Discovery command the script ran | `ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu` |
| Email address found in the script's comments | `greg@tryhackme.thm` |

The twist in this task is worth sitting with: the investigation starts from a SIEM alert about a spike in Discovery commands, exactly the kind of alert an attacker would trigger, but walking the process tree back from `hostname` leads to `/home/itsupport/debug.sh`, a script with an author's email address sitting right in the comments. This is a false positive, and recognizing it as one is the actual skill being tested. A `whoami` spawned by a web server process is a red flag. The same command run from a named IT admin's debug script is Tuesday. Building a process tree does not just confirm an attack, it just as often rules one out, which matters just as much for an analyst's time and an organization's alert fatigue.

**Step 3: Detect Ingress Tool Transfer, and know which log to check.** Task 4 puts two downloads side by side and asks which one is more likely malicious.

| Question | Answer |
|---|---|
| Domain the Elastic agent was downloaded from | `artifacts.elastic.co` |
| Path to the downloaded `helper.sh` script | `/var/tmp/helper.sh` |
| More likely malicious download: curl or wget | `curl` |

Both downloads used a preinstalled tool and left a record in auditd, so the difference is not the transfer mechanism, it's the destination and the source. `artifacts.elastic.co` is Elastic's real, official domain, downloading a known monitoring agent. The `curl` download pulled `helper.sh` from a lookalike domain built to resemble Dropbox, landing in `/var/tmp`, a staging location with no legitimate reason to hold anything. Domain reputation plus destination path does the same job a malware scan would, without needing to touch the file at all.

The directionality problem covered in the room's own text deserves the emphasis it gets. An attacker running `scp` from their own machine to push a file onto the victim leaves only an SSH login in `auth.log`, since the `scp` process itself runs on the attacker's box, not the victim's. Flip the direction, the victim's shell pulling a file from the attacker's server, and the opposite log source lights up: auditd catches the `scp` or `curl` process directly, and `auth.log` shows nothing unusual. The same principle extends to FTP and SMB. A SOC investigating a suspected Ingress Tool Transfer needs to check both directions before concluding a log source came up empty.

**Step 4: Follow Dota3 from brute force through Discovery.** Task 5 introduces Dota3, a real cryptomining botnet that SANS ISC honeypot research and CounterCraft's threat intelligence team have both tracked since at least 2019 to 2021, still active as of the most recent reporting. It shares its lineage directly with Outlaw, the SSH brute-forcing botnet covered in Linux Threat Detection 1: Elastic Security Labs lists Outlaw and Dota as the same threat cluster operating under two names, and the `dota3.tar.gz` payload referenced throughout this room is the exact archive filename researchers have documented in the wild.

According to the room's account, Dota3's botnet spans more than 2,000 distinct IPs across 94 countries, brute-forcing `root` with the top 1,000 weakest passwords rather than anything sophisticated. Once a guess lands, the Discovery phase runs in seconds: CPU model, RAM size, and cron jobs, the same CPU-and-memory check pattern that immediately signals a cryptominer rather than a data stealer or a botnet recruiter, since almost nothing else needs to know how many cores a victim has.

| Question | Answer |
|---|---|
| IP that brute-forced the exposed SSH | `45.9.148.125` |
| Command used to list recently logged-in users | `last` |
| Three EDR processes searched for with `egrep` | `ds_agent, falcon, sentinel` |

Those three process names are not made up for the room. `ds_agent` is the real Linux process name for Trend Micro's Deep Security Agent, `falcon` for CrowdStrike Falcon, and `sentinel` for SentinelOne, three of the most widely deployed EDR products on real Linux fleets. An attacker grepping for exactly those three names is doing the same reconnaissance a penetration tester would do before deciding whether to proceed quietly or make noise.

The persistence step that follows Discovery is where Dota3 gets its bite: it resets the compromised account's password to a long, attacker-chosen string, then deletes the `.ssh` directory entirely and replaces it with a single authorized key carrying the comment `mdrfckr`, a distinctive enough string that researchers use it as a standalone indicator of compromise for this exact malware family. The password change is framed, almost politely, as protecting the victim from competing botnets. The practical effect is that the legitimate owner is locked out of their own server.

**Step 5: Trace the miner deployment to completion.** Task 6 finishes the infection chain: cryptominer and scanner tools arrive over SCP using the freshly stolen credentials, get unpacked into a deliberately obscure hidden folder, and launch.

| Question | Answer |
|---|---|
| Malicious archive transferred via SCP | `kernupd.tar.gz` |
| Full command line of the cryptominer launch | `nohup /tmp/.apt/kernupd/kernupd` |
| IP range scanned for exposed SSH | `10.10.12.1-10.10.12.10` |

The staging folder naming, `.X26-unix` in the room's worked example, `.apt` in the graded scenario, mimics real system directories closely enough to survive a bored analyst's glance at a `ls -la /tmp` output. Both binaries launch under `nohup`, which detaches them from the terminal session so they keep running after the SSH connection that started them closes, a small detail that maps to MITRE's Resource Hijacking (T1496) for the miner itself and Hide Artifacts (T1564.001) for the hidden staging directory. The network scan for more victims, the same `tsm` tool from the room's own walkthrough, is Dota3 propagating exactly the way a worm does: compromise one host, then use it to find the next.

## Why it matters

Three lessons in this room outlast the specific IOCs. The first is the `whoami` rule itself: a single command, almost never run by legitimate software, run by nearly every attacker, is rare enough in security to be worth memorizing on its own. The second is the itsupport/debug.sh story, proof that Discovery-spike alerts need the same process tree scrutiny whether they turn out to be an attack or a Tuesday. A SOC that treats every Discovery alert as confirmed malicious burns analyst time and credibility fast, and a SOC that treats every Discovery alert as noise misses Dota3's first move.

The third lesson is the one this room shares with Linux Threat Detection 1 without repeating itself: Dota3 and Outlaw are the same lineage, tracked under two names by two different research teams, running the identical playbook, SSH brute force, immediate CPU and memory checks, an SSH key swap for persistence, an XMRig payload staged in a hidden `/tmp` folder. This chain has been running largely unchanged since before 2020 and remains active today, succeeding on familiarity rather than sophistication: weak SSH passwords stay common enough that a botnet spanning 94 countries can still find new victims every day.

This room completes the arc the series has built. Linux Logging for SOC taught which logs exist. Linux Threat Detection 1 taught how Initial Access shows up in those logs and how to trace it with a process tree. This room shows the same process tree method working against Discovery and tool transfer, then proves it against a botnet that has been running the same playbook for years.

## Key takeaways

- `whoami` is close to a single-command detection rule on Linux: legitimate software rarely runs it, attackers almost always do, first.
- The same Discovery command can be an attack or routine IT work. Process tree context, not the command itself, is what tells them apart.
- Which log source shows an Ingress Tool Transfer depends on which side initiated the connection: the attacker pushing a file leaves a login in `auth.log`, the victim pulling one leaves a process in auditd.
- Domain reputation and destination path can separate a malicious download from a legitimate one even when both used the same tool and left the same kind of log entry.
- Dota3 and Outlaw are the same botnet lineage tracked under two names, still actively brute-forcing exposed SSH servers years after researchers first documented the pattern.
- A distinctive artifact, like the `mdrfckr` SSH key comment, can serve as a standalone indicator of compromise for an entire malware family.