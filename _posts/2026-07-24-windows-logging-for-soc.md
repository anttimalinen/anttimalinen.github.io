---

title: Windows Logging for SOC

date: 2026-07-24 13:00 +0300

categories: [Foundations, Windows]

tags: [windows, event-logs, sysmon, powershell, log-analysis]

description: "How Windows Security, Sysmon, and PowerShell logs work together to trace an attacker from RDP brute force through backdoor account creation, malware execution, and startup persistence to command and control."

---

## Description

The "Windows Logging for SOC" room from TryHackMe's SOC Level 1 path builds the log-reading foundation every Windows-focused SOC analyst needs before touching a SIEM. It walks through Event Viewer's binary log format, the two Security log events that catch most RDP attacks (4624 and 4625), the user management events that reveal backdoor accounts, Sysmon's process and network telemetry, and the PowerShell history file that survives when nothing else logs a command.

The room closes with two practice files dropped on the lab desktop: `Practice-Security.evtx` and `Practice-Sysmon.evtx`. Both hold a real, self-contained intrusion. An attacker brute-forces RDP, logs in as Administrator, and creates a backdoor account. Separately, a user named Sarah downloads and runs a malicious executable that phones home and persists through a Startup folder shortcut. Every answer below came from working through those two files and the PowerShell history exercise on the lab VM, matched against the room's confirmed answers.

The room sits deliberately late in the SOC Level 1 path and leans on four earlier rooms: Logs Fundamentals for the basic vocabulary, Sysmon for installing and configuring the tool itself, a room on querying event logs, and Core Windows Processes for telling a legitimate `svchost.exe` from an impersonator. Skipping those and jumping straight here would mean recognizing an event ID without understanding what's normal enough to compare it against, which is most of the actual job.

## The problem

Ask an IT admin whether they'd notice a new local account, and most say yes. Ask them to name the event ID for it, or the log it lives in, and the room goes quiet. That gap between "I'd notice" and "I'd know where to look" separates admins from SOC analysts, and it's why logging is the first real skill in any blue team learning path.

Windows makes this harder than it needs to be. Event logs live in `C:\Windows\System32\winevt\Logs` as `.evtx` files, a binary format no text editor can open. `cat` or `grep` return nothing useful against them; reading one properly requires Event Viewer, `wevtutil`, or PowerShell's `Get-WinEvent`. Security logs alone define north of 500 documented event IDs, with several thousand more spread across the rest of the system. Most of them aren't logged by default. Process creation, one of the single most useful signals a SOC analyst has, sits behind Event ID 4688, and Windows won't generate it until someone manually enables advanced audit policy.

PowerShell compounds the problem. A single `powershell.exe` process can run hundreds of distinct commands in one session, read files, enumerate users, download payloads, all without spawning a single additional process for Sysmon to catch. Sysmon Event ID 1 shows `powershell.exe` launched once, with nothing about what happened inside it. Script Block Logging, the feature that actually captures command content, generates Event ID 4104 and is also off by default.

Part of the reason so much stays disabled is Windows ships two separate audit policy systems. Basic Audit Policy, the older one, toggles broad categories with almost no granularity. Advanced Audit Policy, the one every serious environment should run instead, breaks those same categories into dozens of subcategories, letting an admin enable "Audit Process Creation" without also turning on every other type of object access logging in the same bucket. Most default installs never touch either setting past whatever the out-of-box template configured, which is exactly why 4688, 4104, and file or registry auditing sit dark on so many machines until someone deliberately flips them on.

None of this is academic. Verizon's 2026 Data Breach Investigations Report found vulnerability exploitation overtook stolen credentials as the leading initial access vector for the first time, accounting for 31% of breaches, while credential abuse fell to 13%. That shift doesn't retire the Security log. Credential abuse still shows up in 39% of full breach chains once you look past the initial access point, and infostealers are surfacing an average of 2,362 breached corporate credentials a month from organizational email domains alone. Seventy-three percent of ransomware victims had an infostealer infection or a credential leak in the year before the attack hit. Attackers get in through a vulnerability, then move like a legitimate user, and the logon, account management, and process events this room teaches you to read are the only record of that movement.

## How it works

**Step 1: Read the raw log before trusting any tool's summary of it**

Event Viewer parses the binary `.evtx` format into four working areas, and knowing where to look cuts triage time more than memorizing any single event ID does.

| Panel | What it shows |
|---|---|
| Log Sources | Left pane, one entry per `.evtx` file. Application logs cover user-mode software like IIS or SQL Server, Security logs cover logons, process activity, and account changes |
| Log List | One row per event, sortable by Keywords (success or failure for some event types), Date and Time (system time, not UTC), and Event ID |
| Log Details | The full event content, plaintext or XML, under the "Details" tab |
| Filters Menu | "Filter Current Log" and "Find" narrow thousands of events down to the ones worth reading |

A handful of log channels come up constantly enough to know by name before touching a single filter.

| Log channel | Typical contents |
|---|---|
| Security | Logons, logoffs, account management, object access (needs audit policy enabled) |
| System | Service start/stop, driver load failures, unexpected reboots |
| Application | Errors and warnings raised by installed software |
| Applications and Services Logs > Microsoft > Windows > Sysmon > Operational | Sysmon telemetry once installed |
| Applications and Services Logs > Microsoft > Windows > PowerShell > Operational | Script Block Logging events, once enabled |

Security logs alone cover more than 500 documented event IDs, and the total across every log source runs into the thousands. Not every source is enabled out of the box, which is the first thing to check before assuming a log will have what an investigation needs. In the room's opening screenshot, the successful login is logged as `Security / 4624`, the pairing analysts memorize early and never forget.

Event Viewer's GUI is fine for a first pass, but pulling a specific event ID out of a large `.evtx` file is faster from PowerShell. `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}` filters to failed logons directly, and swapping the `LogName` and `Id` values covers every source in this room, including the offline `.evtx` files by adding a `Path` key instead of `LogName`.

| Task | Command pattern |
|---|---|
| Failed logons from a live Security log | `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}` |
| Any event ID from an offline `.evtx` file | `Get-WinEvent -FilterHashtable @{Path='Practice-Security.evtx'; Id=4720}` |
| Sysmon process creation events | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1}` |
| PowerShell script block events | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104}` |

`wevtutil qe` does the same job from the command line for anyone working without PowerShell's module loaded, at the cost of noticeably uglier output.

**Step 2: Correlate authentication events to catch brute force before it becomes a breach**

Two event IDs carry most of the weight in the Security log.

| Event ID | Purpose | Logged where | Limitation |
|---|---|---|---|
| 4624 (Successful Logon) | Spot suspicious RDP or network logins and find where an attack started | On the machine being accessed | Noisy. Loaded servers generate hundreds of these a minute |
| 4625 (Failed Logon) | Spot brute force, password spraying, or vulnerability scanning | Same machine | Inconsistent. Plenty of caveats can lead to a wrong read of the event |

A 4624 event carries four fields worth checking every time: Logon ID, Logon Type, the username, and the source IP or hostname. Logon Type tells you how someone got in.

| Logon Type | Meaning |
|---|---|
| 2 | Interactive, console logon |
| 3 | Network logon (file shares, most RDP with NLA) |
| 7 | Unlock |
| 10 | RemoteInteractive, RDP without NLA |

A 4625 carries a Sub Status code worth reading past the headline event ID, since it explains why the logon actually failed.

| Sub Status | Meaning |
|---|---|
| 0xC000006A | Wrong password for a valid username |
| 0xC0000064 | Username doesn't exist |
| 0xC0000234 | Account is currently locked out |
| 0xC0000072 | Account is disabled |

A wave of `0xC000006A` failures against the same username, arriving seconds apart, is the fingerprint of an automated brute force tool rather than someone fumbling their own password.

Detection here means correlating failed authentication attempts with a subsequent successful login from the same source, since that pattern points to a compromised credential rather than a one-off typo. The workbook for hunting RDP brute force runs like this: filter Security logs for 4625, isolate Logon Type 3 or 10 (3 is standard once Network Level Authentication is on, 10 shows up on older or misconfigured hosts), then flag anything with multiple usernames tried against one host, many failures against a single account, or a source IP and hostname that don't match anything in the environment.

Running that against `Practice-Security.evtx` on the lab machine surfaced a clean brute force pattern. `10.10.53.248` fired repeated failed logons before landing a successful one against the `Administrator` account, Logon Type 10, confirming RDP as the entry point. The malicious RDP session carried Logon ID `0x183C36D`, a value worth writing down immediately, because everything the attacker does next inherits that same ID.

Nation-state groups like Volt Typhoon lean almost entirely on valid credentials instead of deploying malware, which makes their activity blend into normal administrative traffic and evade tools built to catch obviously malicious binaries. That's the whole reason this event pairing matters more than its noise level suggests. A stolen or brute-forced credential doesn't trip an antivirus alert. It trips a logon event, and only someone reading that log actually sees it.

**Step 3: Follow the Logon ID into user management events to catch the backdoor account**

Once an attacker has a foothold, the next move is usually persistence that survives a password reset. Windows logs that too, under a small, memorable set of event IDs.

| Event ID | Description | Malicious usage |
|---|---|---|
| 4720 / 4722 / 4738 | Account created / enabled / changed | Attackers create a fresh backdoor account or reactivate a dormant one to dodge detection |
| 4725 / 4726 | Account disabled / deleted | Sometimes used to slow down SOC response by disabling legitimate accounts |
| 4723 / 4724 | Password changed / reset | With enough privilege, an attacker resets a target's password to lock them out and take over |
| 4732 / 4733 | Added to / removed from a security group | The classic move: drop a backdoor account into a privileged group |

Every user management event splits into the same three parts: Subject (who did it, including their Logon ID), Object (the account being acted on), and Details (what specifically changed, like a target group or a new account's attributes).

Detection guidance for this technique calls for correlating a 4720 account creation with a subsequent 4732 or 4728 group addition, and flagging anything happening outside normal IT change windows or from an account with no business creating users. A 4720 event followed within about 60 seconds by a 4728 or 4732 event, both under the same subject account, is close to a textbook backdoor sequence and worth treating as a critical finding on its own.

In `Practice-Security.evtx`, that exact sequence shows up. The attacker created a local account named `svc_sysrestore`, a name built to look like a legitimate Windows maintenance service rather than an obvious intruder tool. That account went straight into two privileged groups: Backup Operators and Remote Desktop Users. Neither is Administrators, and that's deliberate. Remote Desktop Users grants RDP access without the scrutiny an outright admin account creation draws. Backup Operators is the quieter but more dangerous choice: membership carries `SeBackupPrivilege` and `SeRestorePrivilege`, which let an account bypass NTFS file permissions entirely for backup and restore operations, including reading the SAM and NTDS.dit files that hold every password hash on the box. A backup account can walk out with the crown jewels without ever touching Administrators.

Pulling the Logon ID off the `svc_sysrestore` creation event and comparing it against the RDP logon from Step 2 confirms they match, `Yea`, tying the entire chain back to the single session that started with the brute-forced Administrator login.

**Step 4: Trace process execution with Sysmon once Security logs run out of detail**

Security logs can tell you someone logged in. They can't tell you what that someone ran, unless 4688 process creation is manually enabled, and even then the fields are thin.

| Log source | Purpose | Limitation |
|---|---|---|
| 4688 (Security: Process Creation) | Logs every new process, including command line and parent process | Off by default, requires manually enabling advanced audit policy |
| 1 (Sysmon: Process Creation) | Replaces 4688 with richer fields: process hash, digital signature, and more | Sysmon is a separate Microsoft Sysinternals install, not built into Windows |

Sysmon Event ID 1 groups its fields into four buckets: Process Info (PID, image path, command line), Parent Info (the launching process, essential for building an attack chain), Binary Info (hash and signature, useful for checking a file against VirusTotal), and User Context (which user ran it, plus the same Logon ID field from the Security log). That shared Logon ID is what lets an analyst walk seamlessly from an authentication event into what the attacker actually executed.

The workbook for a process launch review: check the process and binary info for an uncommon install path (`C:\Temp`, `C:\Users\Public`), a suspicious or randomly generated filename, or a hash that comes back flagged on VirusTotal. Check the parent process for anything that doesn't make sense, like Notepad spawning `cmd.exe`. If still unsure, walk up the process tree by matching ParentProcessId to a preceding event's ProcessId, repeating the same checks at each level.

`Practice-Sysmon.evtx` documents a separate incident on the same lab: a user named Sarah browsing with Google Chrome downloaded a file to `C:\Users\sarah.miller\Downloads\ckjg.exe`. Chrome's own process events don't carry a URL by default, so pulling that detail required checking other Sysmon events tied to the same process, which surfaced the source: `http://gettsveriff.com/bgj3/ckjg.exe`. Neither the filename nor the domain resembles anything a legitimate download would use, both textbook indicators from the workbook above.

**Step 5: Check file, registry, and network events for what happens after execution**

Process creation alone misses where a dropped file lands, what it touches in the registry, and where it talks to over the network. Four more Sysmon event IDs close that gap.

| Event ID | Security log alternative | Purpose |
|---|---|---|
| 11 / 13 (File Create / Registry Value Set) | 4656 and 4657, both off by default | Catch dropped files or registry changes, often persistence mechanisms |
| 3 / 22 (Network Connection / DNS Query) | None direct, needs firewall or DNS logging separately | Catch traffic from untrusted processes or connections to known-bad infrastructure |

Every one of these events shares the same process-context fields as Event ID 1, but drops the Logon ID and parent process info, so the workflow is always the same: grab the ProcessId from the file or network event, find the matching Event ID 1, and pull full context there.

Sysmon's file creation event (ID 11) is the standard way to catch new files landing in the per-user or all-users Startup folder, the classic location Windows checks for programs to launch automatically at logon. `Practice-Sysmon.evtx` shows exactly that: the malware Sarah ran dropped a file named `DeleteApp.url` into `C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`. A `.url` shortcut in that folder runs automatically at every logon, no registry key required and no admin privilege needed to place it. This mirrors real intrusions tracked under the same technique, including a 2025 campaign where a PowerShell script copied a payload into AppData and dropped a Startup Folder shortcut for the AdaptixC2 framework.

The network side of the same investigation turned up a connection to `193.46.217.4:7777`, resolving to the domain `hkfasfsafg.click`. Port 7777 isn't a standard service port for anything Windows runs natively, and that mismatch is the tell. Adversaries routinely pair a protocol with a port it isn't normally associated with, the same way some campaigns run HTTPS over port 8088 instead of the standard 443, specifically to slip past filtering and complicate traffic analysis. It's the same logic behind well-known offensive defaults like Meterpreter's reverse shell on port 4444, chosen precisely because it doesn't match what a firewall or analyst expects to see on that port. A `.click` TLD paired with a random high port is exactly the kind of network connection event worth escalating on sight, long before any file hash comes back as confirmed malware.

**Step 6: Pull PowerShell command history when nothing else caught what ran**

PowerShell needs its own log source because Sysmon and Security logs both stop at "powershell.exe was launched." The simplest, always-on record of what happened inside that session is a plain text file.

| Detail | Value |
|---|---|
| Location | `C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` |
| Created by | PowerShell automatically, updated the moment Enter is pressed |
| Survives reboot | Yes, unless manually deleted |
| Per-user | Yes. Multiple active users means multiple history files to check |
| Limitation | No command output, and no visibility into script content when a `.ps1` file is run directly |

Reviewing the Administrator's history file on the lab VM, the first command run was `Get-ComputerInfo`, timestamped May 18, 2025 based on the file's own properties. Checking other local users' history files on the same box turned up a flag planted in one of them: `THM{it_was_me!}`.

The history file is a starting point, not a complete record, and that gap is worth knowing before relying on it in a real investigation. PowerShell Script Block Logging, Event ID 4104, captures the actual script content after PowerShell's parser has already resolved Base64 encoding, string concatenation, and variable substitution, which the history file never does. Windows even flags some suspicious script blocks as Warning-level events under 4104 automatically, using built-in keyword heuristics, even in environments where full script block logging was never deliberately turned on. The catch: 4104 is disabled by default, same as 4688, and needs a Group Policy change before it starts populating the `Microsoft-Windows-PowerShell/Operational` log.

A neighboring event ID, 4103, gets confused with 4104 often enough to be worth separating clearly.

| Event ID | Name | Captures |
|---|---|---|
| 4103 | Module Logging | Which cmdlets and modules ran, with their parameters. Lighter weight, doesn't show the full script |
| 4104 | Script Block Logging | The complete, deobfuscated script text itself |

4103 tells an analyst that a suspicious cmdlet ran with a particular parameter, while 4104 shows the entire surrounding script that cmdlet came from, which makes 4104 the higher-signal source of the two for hunting. Both share the same limitation as the history file's opposite number: they need to be turned on before an incident, not after. Even with full PowerShell logging enabled, gaps remain around non-PowerShell script hosts like VBScript, JScript, and WMIC, which is exactly why PowerShell logging and Sysmon are meant to run together rather than as substitutes for each other.

**Step 7: Put the whole chain on the ATT&CK matrix**

Read `Practice-Security.evtx` and `Practice-Sysmon.evtx` as one continuous story instead of two separate exercises, and the value of correlation stops being theoretical. `10.10.53.248` brute-forces RDP, lands a valid Administrator session under Logon ID `0x183C36D`, and uses that exact session to create `svc_sysrestore` and drop it into Backup Operators and Remote Desktop Users, all confirmed by matching Logon IDs across the 4624 and 4720 events. On a different track through the same lab, Sarah's Chrome download of `ckjg.exe` gives Sysmon a ProcessId to chase through Event IDs 1, 11, and 3, surfacing the Startup folder persistence and the C2 callback in turn. Two unrelated-looking incidents, four Windows event sources, and the entire trail holds together because two fields, Logon ID and ProcessId, never stop pointing back to their source.

That's the muscle memory this room is actually building. One attack chain emerges across five MITRE ATT&CK techniques, each traceable to a specific log source covered above.

| Stage | Technique | Log evidence |
|---|---|---|
| Initial access | T1078, Valid Accounts (via brute force) | Security 4625 wave, then 4624 with Logon Type 10 |
| Persistence | T1136.001, Create Account: Local Account | Security 4720 for `svc_sysrestore`, 4732 for group membership |
| Execution | T1204.002, User Execution: Malicious File | Sysmon Event ID 1 for `ckjg.exe`, parent process Chrome |
| Persistence | T1547.001, Registry Run Keys / Startup Folder | Sysmon Event ID 11 for `DeleteApp.url` |
| Command and Control | T1571, Non-Standard Port | Sysmon Event ID 3 to `193.46.217.4:7777` |

T1204.002 covers exactly this pattern, an adversary relying on a user to open a malicious file to trigger execution, typically as follow-on behavior once a file has already reached the victim's machine. None of these five techniques are obscure. They're the ones an analyst runs into constantly, which is exactly why the room drills them instead of something rarer.

**Step 8: Sketch a detection rule from what the logs showed**

Working an incident after the fact is one skill. Writing a rule so the SIEM catches the next one automatically is a different, related skill worth practicing on the same data. The brute force and backdoor account chain above translates into a correlation rule with three conditions chained together: five or more `4625` events within two minutes against the same target account, followed by a `4624` from the same source IP with Logon Type 10, followed within an hour by a `4720` where the Subject Logon ID matches that same 4624. Any SIEM with sequence or correlation search support, Splunk's `transaction` command, Sentinel's KQL `join`, or Elastic's EQL sequences, can express that chain directly. The persistence and C2 half of the investigation follows the same pattern: a Sysmon `11` event with a target path containing `\Start Menu\Programs\Startup\`, correlated by ProcessId to a `3` event connecting outbound on a port outside the common list (80, 443, 445, 3389, and a handful of others). Writing the rule out in plain language before touching SIEM syntax is what actually transfers between platforms; the query language changes, the logic never does.

## Why it matters

Every technique in this room maps onto tasks a Level 1 SOC analyst handles in the first hour of a shift: triage a flood of failed logons, confirm whether a new local account is legitimate, trace a malicious download back to its source, and figure out whether an infected host is still talking to its command server. None of that requires exotic tooling. It requires knowing which of Windows' thousands of event IDs actually matter and how to string them together using two correlation keys: Logon ID for anything tied to a user session, ProcessId for anything tied to a running process.

The shift toward vulnerability exploitation as the top initial access vector doesn't make this skill set less relevant. An attacker who gets in through an unpatched service still needs to authenticate somewhere, still needs persistence that survives a reboot, and still needs to talk to infrastructure they control. Every one of those steps generates the exact event types this room walks through: a logon, an account change, a process launch, a network connection. Vulnerability exploitation changes the front door. It doesn't change what happens after someone's inside, and that's the part this room actually teaches an analyst to see.

Three concrete scenarios show why this matters beyond the lab. A Tier 1 analyst gets paged for a spike in 4625 events against a domain controller. Knowing to check the Sub Status code and Logon Type in seconds, rather than escalating blind, is the difference between closing a false positive from a misconfigured service account and catching a live password spray before it succeeds. Separately, an EDR alert fires on an unfamiliar process. Pulling the Sysmon Event ID 1 for that ProcessId, then checking Event IDs 3 and 11 for the same process, turns a single vague alert into a full chain: what ran, what it dropped, and where it phoned home, all before a Tier 2 escalation is even needed.

The third scenario is quieter and easier to miss. A help desk ticket mentions a new service account nobody remembers requesting. Nothing about that ticket looks like an incident. Pulling the 4720 for that account, checking who created it and whether a 4732 followed within a minute, either clears it in two minutes or surfaces exactly the kind of backdoor account this room trains an analyst to recognize on sight. The skill isn't reacting to alerts. It's knowing which mundane-looking questions deserve a log check before being waved off.

The other differentiator worth naming: most of the useful log sources here (4688, 4104, and every registry or file audit event) are off by default. An analyst who only knows how to read a SIEM dashboard someone else configured is at the mercy of whatever that person remembered to enable. An analyst who knows the underlying event IDs can tell, at a glance, whether a log source has a real gap or whether the evidence just isn't there yet, and that distinction is worth more in an interview than any tool certification.

## Key takeaways

- Security log 4624 and 4625 form the backbone of authentication triage. Correlate failed attempts with a subsequent success from the same source, and check the Sub Status code, to catch brute force and credential-based access.
- Logon ID is the thread that ties a logon event to everything an attacker does afterward, including account creation and group membership changes. Always pull it and check for a match.
- User management events (4720, 4732, and related IDs) reveal backdoor accounts. A new account followed quickly by a privileged group addition is close to a guaranteed red flag, and Backup Operators is a quieter privilege escalation path than Administrators.
- Sysmon Event ID 1 replaces the disabled-by-default 4688 with richer process context. ProcessId links it to file, registry, and network events for the same process.
- Startup folder drops and non-standard C2 ports are both well-documented, well-detected persistence and command-and-control patterns, not exotic techniques.
- PowerShell's history file is useful but incomplete. Script Block Logging (4104) captures deobfuscated script content the history file never will, at the cost of needing to be enabled first.