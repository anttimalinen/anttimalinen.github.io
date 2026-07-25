---

title: Windows Threat Detection 1

date: 2026-07-25 14:00 +0300

categories: [Foundations, Windows]

tags: [windows, initial-access, phishing, rdp, sysmon]

description: "How exposed RDP, misleading file extensions, LNK-based PowerShell payloads, archive phishing, and infected USB drives each leave a distinct Windows event trail, and how to trace all four back to their MITRE ATT&CK Initial Access technique."

---

## Description

"Windows Threat Detection 1" picks up exactly where Windows Logging for SOC leaves off. That room taught which Windows event IDs exist and where to find them. This one hands you four real Initial Access scenarios, exactly the kind of alert that lands on a Tier 1 queue, and asks you to work out how the attacker got in using nothing but the logs already covered: Security authentication events and Sysmon process, file, and network telemetry.

The room splits Initial Access into two families, exposed services and user-driven compromise, then backs each one with a practice scenario built around real MITRE ATT&CK techniques: a brute-forced RDP server, three separate phishing attachments, and an infected USB drive. Every answer below came from working through `RDP-Security.evtx`, the three folders under `Phishing Case 1-3`, `Phishing-Sysmon.evtx`, and `USB-Sysmon.evtx` on the lab VM, matched against the room's confirmed answers.

Completing Windows Logging for SOC first isn't optional busywork here. Half the workbooks in this room assume fluency with Logon ID and ProcessId correlation, the two fields that carried every investigation in that earlier post.

## The problem

Picture Windows machines as buildings with two kinds of entrances. Some have a front door facing the street, an exposed service like RDP, a mail server, or a web application, built to let legitimate people in remotely. Others have no street-facing door at all, and the only way in is if someone inside opens it, by clicking an attachment or plugging in a USB drive someone else already left in the hallway. Every Initial Access technique in this room falls into one of those two families.

| Family | MITRE technique | How it works |
|---|---|---|
| Exposed services | T1133, External Remote Services | Adversaries authenticate to internet-facing RDP, VPN, or similar remote access with valid or brute-forced credentials |
| Exposed services | T1190, Exploit Public-Facing Application | Adversaries exploit a software bug or misconfiguration in an internet-facing app, no credentials needed |
| User-driven | T1566, Phishing | Adversaries trick a user into opening a malicious attachment or link themselves |
| User-driven | T1091, Replication Through Removable Media | Adversaries infect a USB device and hope it gets plugged into a new machine |

The exposed-service half of that table is a numbers game as much as a technical one. RDP scanning happens constantly and automatically. Bulletproof hosting providers run continuous credential-stuffing sweeps against port 3389 using RDP cookie values like `mstshash=Administrator`, the exact fingerprint of a bot trying the default admin account before anything else. Put an RDP port on the internet with a weak password and the only question is how many hours pass before it's found, not whether.

The user-driven half is worse in a different way, because no firewall rule fixes it. A user with internet access will eventually bring something bad back to their laptop themselves, bypassing every perimeter control in one click. The scale is real: total phishing volume hitting email filters has climbed roughly 41-fold since ChatGPT's release in 2022, and Windows still ships with known file extensions hidden by default, meaning `invoice.pdf.exe` displays to a user as `invoice.pdf`. That single default setting, present in Windows since the 1990s, is doing more work for phishing attackers than any exploit kit.

Modern email filtering has pushed attackers toward formats that dodge automated scanning rather than outright blocking. Archives sidestep content inspection that a plain executable attachment would trigger immediately. ISO and IMG disk images get special treatment from Windows too: files extracted from an ISO don't inherit the Mark of the Web flag that normally makes Windows warn before running something downloaded from the internet, so a malicious executable packed inside an ISO can launch with zero security prompts at all. None of this requires a zero-day. It only requires knowing which Windows defaults an attacker can lean on instead of fight.

Mandiant's M-Trends 2025 report, the exact source this room points to, puts email phishing at 14% of identified initial infection vectors for 2024, down from 22% in 2022, trailing behind exploited vulnerabilities at 33% and stolen credentials at 16%. Phishing declining in the aggregate doesn't mean it declined in this room's scope, though. It means attackers increasingly reach for whichever door opens fastest, and for a huge share of small and mid-sized organizations without a dedicated vulnerability management program, phishing and an exposed RDP port remain exactly that.

## How it works

**Step 1: Sort every alert into exposed-service or user-driven before touching a single log**

Before opening Event Viewer, the fastest triage decision is which of the two families an alert belongs to, since that determines which log source actually has the answer.

| Question | If yes | If no |
|---|---|---|
| Did the activity originate from an external IP hitting a service the org runs? | Check Security log authentication events (4624/4625) | Check Sysmon process and file events instead |
| Did a user need to click, open, or plug something in first? | Check Sysmon Event ID 1 and 11 around that user's session | Look for T1133/T1190 exploitation patterns instead |

A vulnerable mail server getting exploited is `T1190`, Exploit Public-Facing Application, since the mail service itself is the internet-facing target and no user interaction is required. A user opening a malicious email attachment is `Phishing`, `T1566`, since the entire technique depends on that click. Mixing these up wastes the first ten minutes of triage checking the wrong log source entirely.

The same `Get-WinEvent` patterns from the Windows Logging for SOC investigation carry over directly, just pointed at new event IDs and new offline files.

| Task | Command pattern |
|---|---|
| Failed RDP logons from an offline `.evtx` | `Get-WinEvent -FilterHashtable @{Path='RDP-Security.evtx'; Id=4625}` |
| Sysmon file creation events for a phishing case | `Get-WinEvent -FilterHashtable @{Path='Phishing-Sysmon.evtx'; Id=11}` |
| Sysmon DNS query events for a specific process | `Get-WinEvent -FilterHashtable @{Path='Phishing-Sysmon.evtx'; Id=22} \| Where-Object {$_.Message -match '5484'}` |
| USB-origin process creation events | `Get-WinEvent -FilterHashtable @{Path='USB-Sysmon.evtx'; Id=1} \| Where-Object {$_.Message -match 'E:\\'}` |

**Step 2: Reconstruct an RDP breach end to end using only Security logs**

The room's RDP scenario mirrors a real, common setup: an admin exposes RDP on a production server for weekend access, sets the credentials to something guessable, and within hours a botnet finds it. Reconstructing that from `RDP-Security.evtx` follows the same four-stage pattern every RDP breach leaves behind.

| Stage | What happened | Where to look |
|---|---|---|
| Network scan | Botnet finds the exposed port | Out of scope for Windows logs |
| Brute force | Botnet tries common usernames | Security 4625, Logon Type 3 or 10, external source IP |
| Initial Access | Botnet guesses the right password | Security 4624, same filter, check the account name |
| Post-compromise | Attacker logs in interactively | Security 4624, Logon Type 10, pull the Logon ID |

Filtering `RDP-Security.evtx` for 4625 and scanning the Account Name field shows `Administrator` targeted far more than any other username, the default account every RDP brute-force tool tries first because it exists on nearly every Windows install by default. Switching the filter to 4624 and isolating Logon Type 10 surfaces the successful breach: source IP `203.205.34.107` landed an interactive RDP session. That's a different attacker, different IP, and a different evidence file from the Windows Logging for SOC investigation, worth noting explicitly since it would be easy to mix up two separately answered RDP scenarios that share the same shape. The Sub Status codes on the 4625 events here follow the same reference covered in that earlier post, worth checking again any time a 4625 wave shows up in a new investigation rather than assuming every wave is the same tool.

The Workstation Name field on that same 4624 event is a dead end here. It just echoes the victim server's own name rather than the attacker's real machine, a quirk worth knowing before wasting time on it. The real hostname surfaces by pulling the Logon ID off that successful 4624 and pivoting into Sysmon Event ID 1 for any process created under the same Logon ID. The attacker's commands, run interactively during that RDP session, carry their real workstation name in the process context: `DESKTOP-QNBC4UU`. Same correlation technique as the previous room, Logon ID bridges Security and Sysmon every time.

**Step 3: Recognize binary attachments hiding behind a familiar extension**

Windows has hidden known file extensions by default since long before most current SOC analysts were using computers, and phishing attackers have never stopped exploiting it. A file named `program.exe` displays to the average user as just `program`. Rename it `www.skype.com` and it displays as what looks like a link to a video call, not the `.com` executable it actually is.

| Extension | Why it works as a lure |
|---|---|
| `.com` | Reads as a web address, especially with a domain-shaped filename |
| `.scr` | Windows screensaver format, executes exactly like an `.exe` |
| `.cpl` | Control Panel item, opens via `rundll32` and rarely raises suspicion |

Adversaries frequently manipulate both file extensions and icons together, making an attached executable look like a document or match a familiar brand, which is exactly the `www.skype.com` trick in `Phishing Case 1`. Running it as an untrained user would produce the flag `THM{misleading_extension}`, a direct demonstration of how a single Windows default setting turns an obviously malicious file into a plausible one.

The same family shows up stacked in `Phishing Case 3`: a file named `best-cat.jpg.exe`. Explorer hides the final `.exe`, so the file reads as `best-cat.jpg`, an image nobody would think twice about. This exact pattern has its own MITRE sub-technique, `T1036.007`, Double File Extension: a file name carries a secondary extension that causes only the first one to display, while the second extension is what actually determines how Windows opens and executes it. Spotting a double extension on sight, before ever running the file, is the entire skill here.

**Step 4: Trace an LNK shortcut back to the PowerShell command it actually runs**

LNK files are a quieter phishing vector than a straight binary, because a shortcut looks completely legitimate right up until someone checks what it actually points to. A `.lnk` file's "Target" field can hold any command Windows can execute, with the icon and display name set to whatever the attacker wants a user to expect.

`Phishing Case 2` demonstrates the pattern directly: an LNK disguised as a link to a discount announcement actually points to a PowerShell one-liner that downloads and runs a payload. Right-clicking the file and checking Properties, never double-clicking a suspicious LNK to see what it does, reveals the full command and the staging URL: `http://wp16.hqywlqpa.thm:8000/cgi-bin/f`.

A `.lnk` file is a small binary structure, not a script, which is exactly why it evades so much scrutiny. It stores a target path, optional arguments, a working directory, and an icon location, all of which Windows Explorer reads silently and none of which a user sees unless they specifically open Properties. Setting the target to `powershell.exe` with a Base64-encoded argument, and the icon to a PDF or a well-known brand's logo, produces a file that looks and behaves like a document shortcut in every way except the one that matters.

The malware family behind this exact chain, LNK to PowerShell to a downloaded executable, is a live and heavily documented pattern, not a room-only fabrication. Campaigns delivering RemcosRAT through phishing emails with LNK attachments run a PowerShell command that decodes a Base64 payload disguised as a program information file, which then launches the RAT and hands the attacker keylogging, remote shell access, and webcam control. One 2025 campaign using this exact LNK-to-PowerShell chain compromised close to 2,000 WordPress sites to host the staging infrastructure. RemcosRAT itself started life as commercial remote administration software before criminal use turned it into one of the most common RATs seen in phishing campaigns today. The room's simplified version and the real malware family both rely on the exact same weak point: a shortcut file whose actual target nobody checked before double-clicking it.

**Step 5: Follow the Sysmon event chain for archive-based downloads**

Direct executable attachments are getting rarer, since most mail filters catch them outright. Wrapping the payload in a `.zip` or `.rar` archive, then relying on the user to extract and run it, sidesteps a lot of that filtering, and leaves a four-event Sysmon trail that's consistent enough to hunt for directly.

| Order | Event ID | What it captures |
|---|---|---|
| 1 | 1 (Process Creation) | The browser launches |
| 2 | 11 (File Create) | The archive lands in Downloads |
| 3 | 11 (File Create) | The user extracts it somewhere else |
| 4 | 1 (Process Creation) | The user double-clicks the extracted file |

`Phishing-Sysmon.evtx` for `Phishing Case 3` shows exactly that chain. Filtering Event ID 11 for the browser's image path surfaces `top-cats.zip` landing in `C:\Users\Administrator\Downloads\`. Scanning forward through the same event ID shows the target filename shift from Downloads to `C:\Users\Administrator\Pictures\`, the extraction step, a folder chosen deliberately because a Pictures directory full of images draws far less scrutiny than Downloads. Switching to Event ID 1 and searching for a process launching from that Pictures path surfaces the execution event with Process ID `5484`. From there, filtering Event ID 22 (DNS Query) and searching for that same Process ID surfaces the malware's callback: `rjj.store`.

Every step of that chain uses the same technique from the previous room's Sysmon coverage, pivoting on a shared field, here ProcessId instead of Logon ID, to walk from one event type into the next without losing the thread.

**Step 6: Spot Initial Access that started outside the network entirely**

USB-based infection sounds dated next to phishing and cloud-native attacks, but it hasn't gone away. It bypasses every network-perimeter control by design, since the malware never crosses the firewall at all, and it can restart an infection chain even on a machine with no internet access. Two well-documented real-world families make the point. Raspberry Robin, tracked by MITRE as Software S1130, spreads through infected USB devices carrying a malicious LNK object that, on execution, retrieves remote-hosted payloads. Its early infection chain runs a hidden command through `cmd.exe`, which launches `msiexec.exe` to pull the actual malware from an external server, then saves it disguised with a `.tmp` extension for execution. It has served as a precursor to information stealers, Cobalt Strike, and multiple ransomware operations since surfacing around 2022. A separate USB-borne campaign, Camaro Dragon, delivered malware through gift-wrapped drives mailed directly to targets, disguised as promotional hardware.

| USB malware trick | What it looks like to the user |
|---|---|
| Hidden legitimate files, malicious `RECOVERY.lnk` added | A shortcut that looks like it recovers hidden files |
| `Photos.exe` with a folder icon | Looks like a folder, launches as an executable |
| Double-extension copies of every file | `photo_2024_1_12.jpg.exe` reads as a photo |

`USB-Sysmon.evtx` documents the same pattern the room's scenario walks through. Filtering Event ID 1 and searching for a process image path starting with a drive letter other than `C:` surfaces the launch: `E:\Open Sandisk 4GB USB.exe`, a filename engineered to look like a harmless product description rather than malware. Filtering Event ID 11 for the same activity shows the dropped payload landing at `C:\Users\Public\Documents\winupdate.exe`, a path and filename chosen specifically to blend into legitimate Windows Update activity. Continuing through the same file creation events shows the worm behavior completing the loop: it propagates onto a second connected drive, `F:`, ready to infect the next machine it touches.

**Step 7: Put both Initial Access families on one map**

Running all four scenarios back to back turns four separate exercises into one coherent picture of how Initial Access actually breaks down in a real environment.

| Family | Technique | Practice scenario | Primary log source |
|---|---|---|---|
| Exposed service | T1133, External Remote Services | RDP brute force from `203.205.34.107` | Security 4624/4625 |
| User-driven | T1566 + T1036.007, Phishing via double extension | `www.skype.com` and `best-cat.jpg.exe` | Manual file inspection |
| User-driven | T1566, Phishing (LNK) | PowerShell to RemcosRAT via LNK | LNK Properties, PowerShell history |
| User-driven | T1566, Phishing (archive) | `top-cats.zip` to `rjj.store` | Sysmon Event ID 1/11/22 |
| User-driven | T1091, Replication Through Removable Media | `winupdate.exe` from USB | Sysmon Event ID 1/11 |

Four of five rows sit under Phishing, and that imbalance is the point rather than a coincidence. CISA's own advisory on Akira ransomware documents the group using External Remote Services, Exploit Public-Facing Application, and Phishing as initial access methods in real, confirmed incidents, the same three techniques this room drills, alongside credential-based access covered in the prior room. Ransomware operators don't specialize in one Initial Access method. They use whichever door happens to be unlocked.

**Step 8: Sketch a detection rule for each family**

The same habit from the previous room applies here: write the correlation logic in plain language before touching SIEM syntax, since the logic transfers between platforms even when the query language doesn't. The RDP chain becomes a three-stage sequence: ten or more `4625` events within five minutes against a small set of common usernames from one external source IP, followed by a `4624` from that same IP with Logon Type 10, followed by any Sysmon Event ID 1 sharing that Logon ID. The archive-phishing chain becomes a different sequence entirely: a browser process creating a `.zip` or `.rar` file under `Downloads` (Sysmon 11), followed within minutes by a new file created under a different user folder by an archiving tool or Explorer (Sysmon 11 again), followed by a process launch from that second folder (Sysmon 1). The USB chain needs only one condition to be useful as a standing alert: any Sysmon Event ID 1 where the image path's drive letter isn't `C:`, filtered to exclude known removable-media backup tools. None of these three rules needs machine learning or a threat feed. Each one is a direct translation of the manual workbook already walked through above.

**Step 9: Decide which log source to open first, before opening any of them**

A useful habit worth building from this room: before touching Event Viewer, spend ten seconds answering one question, did this alert originate from outside the network hitting an exposed service, or did it start with a user action on an already-trusted device? That single fork decides everything downstream.

| Alert looks like | Start here |
|---|---|
| Spike in failed logons, unfamiliar source IP | Security 4625/4624, filter Logon Type |
| Unfamiliar process, user was browsing | Sysmon Event ID 1, then 11 and 22 for the same ProcessId |
| Unfamiliar process, path starts with a non-C: drive letter | Sysmon Event ID 1, confirm USB origin, then check propagation via Event ID 11 |
| Suspicious file the user hasn't run yet | Right-click Properties before anything else, especially for `.lnk` files |

That last row is worth internalizing on its own. Every other row in this table starts with a log query. This one starts with not running the file, the single highest-leverage action available before an investigation even needs to begin.

## Why it matters

The two Initial Access families in this room map onto two different jobs a SOC analyst does constantly. Exposed-service alerts are a numbers problem, filtering thousands of noisy authentication events down to the handful that matter, using Logon Type and source IP as the filter. User-driven alerts are a pattern-recognition problem, knowing what a legitimate download chain looks like well enough to spot the moment it deviates, whether that's a hidden extension, a shortcut pointing somewhere it shouldn't, or a process launching from a drive letter that has no business running anything.

Both skills show up directly in triage volume. A help desk report of "my computer is acting weird" after opening an email attachment is one of the most common tickets a Tier 1 analyst sees, and the difference between a five-minute investigation and a two-hour one is knowing to check the file's actual extension and the Sysmon chain around it immediately, rather than starting from a full malware scan and working backward. Recognizing an RDP brute force pattern in a 4625 flood, versus escalating every single failed logon as its own incident, is the same kind of leverage applied to authentication logs instead of process logs.

A third scenario ties both families together. An asset management ticket flags an unregistered USB device connected to a finance workstation last week. No alert fired, no antivirus flagged anything, and the device is long gone. Pulling `USB-Sysmon.evtx`-style Event ID 1 and 11 history for that workstation around the connection timestamp either clears it in minutes, because nothing launched from a non-C: path, or surfaces exactly the pattern this room trains an analyst to recognize: a drive-letter-origin process followed by a payload dropped somewhere designed to look routine.

The techniques covered here aren't edge cases reserved for advanced threat actors either. CISA's Akira advisory places External Remote Services, Exploit Public-Facing Application, and Phishing side by side as documented initial access methods from real ransomware intrusions, and Raspberry Robin has sustained USB-based distribution as a viable Initial Access vector for years specifically because organizations underinvest in detecting it relative to phishing and RDP. An analyst fluent in all four of this room's techniques covers a meaningfully larger share of how real ransomware operators actually get in than one who only knows phishing.

The Logon ID and ProcessId correlation habits from the previous room carry forward into every scenario here without exception. That consistency is the actual lesson underneath the four separate stories: Windows logging isn't a different skill for every attack type. It's the same two or three correlation moves, applied to whichever log source the specific technique happens to touch.

The other differentiator worth naming: none of the four techniques in this room require expensive tooling to detect. A 4625 flood, a double extension, an unopened LNK Properties dialog, a drive letter that isn't `C:`, every one of these is visible with Event Viewer alone, no EDR license or SIEM subscription required. An analyst who can work RDP-Security.evtx and USB-Sysmon.evtx cold, without a dashboard doing the correlation for them, brings something a tool-dependent analyst can't replicate: the ability to still function the day the SIEM is down or the client hasn't bought one yet.

## Key takeaways

- Sort every Initial Access alert into exposed-service or user-driven first. That single decision determines whether Security authentication logs or Sysmon process events actually hold the answer.
- RDP brute force leaves a predictable four-stage trail: 4625 failures against common usernames, then a 4624 success, then Logon Type 10 for the interactive session, correlated by Logon ID into Sysmon for what happened next.
- Windows hides known file extensions by default. Treat any filename that could plausibly hide a second extension, or that resembles a domain or brand, as suspicious until confirmed otherwise.
- Never double-click an unfamiliar `.lnk` file. Right-click and check Properties first; the Target field reveals the actual command before it ever runs.
- Archive-based phishing leaves a four-event Sysmon signature: browser launch, archive download, extraction to a new folder, then execution. All four link together through a shared ProcessId.
- USB-based Initial Access still shows up in real ransomware and worm campaigns. A process image path starting with a drive letter other than C: is one of the simplest and most reliable USB indicators available.