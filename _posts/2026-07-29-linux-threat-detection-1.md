---

title: Linux Threat Detection 1

date: 2026-07-29 12:00 +0300

categories: [Foundations, Linux]

tags: [linux, ssh, initial-access, auditd, supply-chain]

description: "How exposed SSH, command injection against a public web app, and a compromised software dependency each leave a trace in Linux logs, and why process tree analysis in auditd catches all three regardless of how the attacker got in."

---

## Description

"Linux Threat Detection 1" takes the log sources from Linux Logging for SOC and puts them to work against real Initial Access scenarios. The room covers three entry vectors in turn: a brute-forced SSH server, a public web application vulnerable to command injection, and a supply chain compromise where a trusted piece of software turns hostile. Underneath all three sits one detection method the room spends real time building: process tree analysis with auditd, tracing a suspicious command back through its parent processes until the true origin of the attack shows up.

Every answer and finding below matches what I confirmed on the platform.

## The problem

SSH sits on almost every Internet-facing Linux server, the same way RDP sits on Windows boxes, and it carries the same tradeoff. It is powerful, convenient, and, when secured only by a password, an open invitation to anyone running a brute-force botnet against port 22. MITRE files both protocols under the same technique, External Remote Services (T1133), because the underlying risk is identical: a remote access service that is one weak credential away from becoming an attacker's front door. Key-based authentication removes the password-guessing angle, but it introduces a different one. A stolen private key, whether lifted from a compromised developer laptop or found sitting in a public GitHub repository, works exactly as well for an attacker as it does for the legitimate owner.

Exploited public-facing services carry a harder problem: the application usually has no idea it is under attack. A web server, a database, a VPN gateway, a CI/CD tool, none of them ship with a log line that reads "currently being exploited." What they leave behind instead are artifacts, a strange query parameter, a spike in errors, a process that has no business existing. MITRE tracks this as Exploit Public-Facing Application (T1190), and detecting it depends entirely on noticing what does not belong rather than reading an alert that announces itself.

Both problems, and a third one covered later in the room, supply chain compromise, converge on the same question: which process actually launched this command, and where did that process come from? Answering that question is what process tree analysis does, and it works whether the entry point was a guessed SSH password, a vulnerable web form, or a backdoored software update. That universality is the room's real argument. Learn one method, apply it to every Initial Access technique that follows.

## How it works

**Step 1: Establish a baseline SSH login.** Task 2 starts with the simplest possible question: when did a known, legitimate user first connect over SSH, and how did they authenticate?

| Question | Answer |
|---|---|
| First SSH login by the `ubuntu` user | `2024-10-22` |
| Authentication method used | `Yea` (SSH key, not a password) |

The distinction between `Accepted publickey` and `Accepted password` in `auth.log` matters more than it looks. Key-based logins mean the connecting client proved possession of a private key, a much stronger guarantee than a password that could have been guessed, phished, or reused from a breached site. Establishing that the `ubuntu` account's normal behavior is key-only turns every future `Accepted password` line for that same account into an anomaly worth investigating on sight, without needing to know anything else about the login.

**Step 2: Detect the SSH brute force.** Task 3 hands over a slice of `auth.log` containing a real compromise: a botnet grinding through password guesses until one lands.

| Question | Answer |
|---|---|
| Date the brute force started | `2025-08-21` |
| Usernames targeted | `root, roy, sol, user` |
| IP that successfully breached `root` | `91.224.92.79` |

The room's own triage framework is worth internalizing: a suspicious SSH login carries at least one of three red flags, password-based authentication instead of a key, a source IP with no business relationship to the organization, and a login time that does not match the account owner's normal pattern. None of the three alone proves a breach, an admin can legitimately use a password from a hotel Wi-Fi at 2 a.m., but a login carrying all three, like the one that lands on `root` in this scenario, moves from "worth a second look" to "assume compromised until proven otherwise."

This scenario is not a hypothetical built for a training room. Elastic Security Labs has tracked a Linux-targeting botnet called Outlaw, also known as Dota, continuously since 2018: it brute-forces SSH using a custom tool called BLITZ, and once it lands a valid password, it adds its own key to the account's `~/.ssh/authorized_keys` file for persistence that survives the next password rotation, then deploys an XMRig cryptominer and coordinates over IRC. A botnet running that exact playbook against a fleet of exposed Linux servers is an active, ongoing threat as of this year, not a retired case study. The account creation and privilege escalation techniques from the Linux Logging for SOC room's auth.log deep dive are the direct follow-up to a breach like this one: once `root` falls to a brute force, everything covered there, backdoored users, `sudo` group additions, becomes the attacker's next move.

The practical fix for this exact attack pattern is boring on purpose: disable password authentication in `sshd_config` in favor of keys only, and layer on rate limiting with a tool like `fail2ban` that watches `auth.log` for repeated failures and temporarily bans the source IP. Neither control stops a targeted attacker with a stolen key, but both remove the entire class of opportunistic, internet-wide brute-force botnets like Outlaw from the threat model, which is most of what hits a random Internet-facing SSH server.

**Step 3: Detect an exploited public service through command injection.** Task 4 introduces TryPingMe, a fictional but entirely realistic internal tool: a web page that takes an IP address, runs `ping -c 2` against it, and returns the result, with no filtering on what the user actually typed into that field.

Command injection is what happens when an application passes user input straight into a system shell without sanitizing it first. TryPingMe's ping field expects an IP address, but nothing stops a visitor from typing `;whoami` instead, and because the application concatenates that input directly into a shell command, the semicolon ends the intended `ping` command and starts a second one of the attacker's choosing.

| Question | Answer |
|---|---|
| Path to the Python file the attacker tried to open | `/opt/trypingme/main.py` |
| Flag found inside that file | `THM{i_am_vulnerable!}` |

The nginx access log tells the whole story once you know what to look for: a source IP submitting normal-looking IP addresses for a while, then suddenly submitting Linux commands, `whoami`, `ls`, and finally a request to read the application's own source code. That last step matters. An attacker who can already run commands on the box still wants to read the code that let them in, both to confirm the vulnerability and to look for hardcoded credentials or additional logic to abuse. MITRE's T1190 covers the initial exploitation, and the room's own list of real precedents holds up well under scrutiny. The Palo Alto firewall CVE it references is almost certainly CVE-2024-3400, a command injection flaw in the GlobalProtect VPN feature that let unauthenticated attackers run arbitrary commands with root privileges on the underlying Linux-based firewall OS, actively exploited in the wild for weeks under the name Operation MidnightEclipse before Palo Alto shipped a fix. The Zimbra Collaboration flaw, the exposed Docker API abused as a cloud entry point, and WordPress's plugin-upload feature turned into web shell delivery round out a pattern that repeats across nearly every category of public-facing Linux software: unsanitized input reaching a shell, one way or another.

**Step 4: Trace the breach with a process tree.** Task 5 is the room's technical core: given a suspicious command, walk the process tree in auditd until you reach the application or user that launched it.

| Field | Purpose |
|---|---|
| `ausearch -i -x <command>` | Find every execution of a specific binary |
| `ppid=` in the result | The parent process ID, your next stop walking upward |
| `ausearch -i --pid <pid>` | Look up a specific process by its PID |
| `ausearch -i --ppid <pid>` | List every child process spawned by a given PID |

| Question | Answer |
|---|---|
| PPID of the suspicious `whoami` command | `1018` |
| PID of the TryPingMe application, found by walking further up | `577` |
| Program used to open the reverse shell | `Python` |

The walk itself is mechanical once you know the pattern: find the command, read its `ppid`, look up that PID, read its `ppid` again, and repeat until the trail ends at PID 1 or at a process you recognize. The method's power lies in not caring what the malicious command was. `whoami` here, `curl | sh` in the room's own worked example, an XMRig miner binary in a real intrusion, the walk-up-the-tree method is identical in every case, because it depends on process ancestry rather than on knowing what to search for in advance.

Wiz Research documented this attack chain in the wild under the name SeleniumGreed: Selenium Grid, a browser-automation tool with no authentication enabled by default, sitting exposed on more than 30,000 internet-facing hosts as of Wiz's July 2024 count. Attackers abuse the Selenium WebDriver API to redirect the browser binary path to a Python interpreter, then pass a base64-encoded script as an argument, which launches Python with a reverse shell that deploys an XMRig miner. Anyone who pulled that intrusion's process tree would see precisely the shape Task 5 builds by hand: a legitimate application process as the root, an interpreter as its child, and the actual malicious payload one level further down. The room's citation of Wiz's Selenium research is not decoration; it is the same technique against a different exposed service.

**Step 5: Recognize advanced and supply chain Initial Access.** Task 6 closes the room with two conceptual questions and a category of attack that process tree analysis is uniquely suited to catch.

| Question | Answer |
|---|---|
| Technique when a trusted app suddenly runs malicious commands | `Supply Chain Compromise` |
| Best detection method across all Initial Access techniques covered | `Process Tree Analysis` |

Supply chain compromise is dangerous because it skips every defense built around the idea of an external attacker breaking in. The malicious code arrives already trusted, bundled inside software the organization chose to install or update. Two real incidents make the stakes concrete. In March 2024, Microsoft engineer Andres Freund noticed SSH logins on a Debian system taking roughly 500 milliseconds instead of the usual 100, investigated the delay out of simple curiosity, and uncovered a backdoor in XZ Utils, a compression library bundled into nearly every Linux distribution, that had been planted over roughly two years of patient social engineering by a contributor using the handle "Jia Tan." The backdoor, tracked as CVE-2024-3094 with the maximum possible CVSS score of 10, would have granted unauthenticated remote code execution through OpenSSH on any system running the compromised version, and it was caught only because one engineer noticed a login taking longer than expected.

A year later, in March 2025, the GitHub Action `tj-actions/changed-files`, used in more than 23,000 repositories, was compromised when an attacker gained access to a maintainer's token and retagged every existing version to point at malicious code. That code dumped the CI runner's memory looking for secrets and printed them, base64-encoded, into public build logs, exposing GitHub tokens, AWS keys, and private RSA keys across every public repository that ran the action during the affected window. Both incidents match the room's own examples, the XZ Utils backdoor and the tj-actions breach it names directly, and both were caught the same way this room teaches: someone noticed a trusted process behaving in a way its history gave no reason to expect.

## Why it matters

Process tree analysis earns the emphasis this room gives it because it is the one technique in the whole intrusion lifecycle that does not depend on knowing the attacker's playbook in advance. An SSH brute force, a command injection against a web app, and a supply chain backdoor look completely different at the point of entry, different logs, different indicators, different MITRE techniques. By the time any of them spawns a process, though, they all produce the same artifact: a parent-child relationship that a defender can walk backward with `ausearch --pid` and `--ppid`, as practiced across Tasks 5 and 6.

The two supply chain incidents covered here are worth sitting with a little longer, because they represent the hardest version of this problem. XZ Utils and tj-actions were not obscure, poorly maintained tools; they were dependencies trusted by millions of installations and tens of thousands of repositories respectively. Neither compromise showed up as a virus scanner hit or a known-bad IP address. Both showed up as something behaving slightly differently than its own history suggested it should, a 500-millisecond SSH delay in one case, an unexpected process spawned by a CI action in the other. Process tree analysis is built for that kind of anomaly, which is why the room treats it as the answer to Task 6's question rather than any single log source.

None of this requires an analyst to predict the next XZ Utils or the next tj-actions in advance. It requires building the habit of asking one question every time a process looks even slightly unfamiliar: what launched this, and does that parent process have any business doing so? Andres Freund did not set out to audit a compression library. He noticed a login was slower than usual and kept pulling the thread. That instinct, not a signature database, is what this room is training.

This room also closes the loop the Linux Logging for SOC room opened. That room taught which logs exist and how to read them; this one puts three of them, `auth.log`, application logs, and auditd, against real attacks and shows that the last one is the only source flexible enough to follow an attacker regardless of how they got in. The room's own closing line points forward on purpose: having learned how these attacks start, the natural next step is learning how they continue once the attacker is inside.

## Key takeaways

- SSH and RDP share the same MITRE technique, External Remote Services, because they share the same failure mode: a remote access point secured by nothing stronger than a guessable credential.
- A login carrying password authentication, an unfamiliar source IP, and an off-pattern login time is not proof of compromise on its own, but all three together is a signal to treat as compromised until proven otherwise.
- Application logs rarely announce an exploit directly. They leave artifacts, injected commands in a URL parameter, a file access that has no legitimate reason to happen, that only make sense once you know what to look for.
- Process tree analysis, walking `ppid` upward through auditd, works identically regardless of whether the entry point was a brute-forced password, a command injection, or a supply chain backdoor.
- Real Linux botnets and supply chain compromises, Outlaw, SeleniumGreed, the XZ Utils and tj-actions incidents, follow the exact patterns this room builds by hand, down to the process relationships an analyst would trace in auditd.
- The most dangerous supply chain compromises are caught by noticing a trusted process behave slightly differently than expected, not by matching a known-bad signature.