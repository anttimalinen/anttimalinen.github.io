---

title: Windows Threat Detection 3

date: 2026-07-27 16:00 +0300

categories: [Foundations, Windows]

tags: [windows, command-and-control, persistence, registry, sysmon, ransomware]

description: "How attackers set up a Command and Control channel after breaching a host, four separate ways they persist through a reboot, and why the ransomware that often follows makes catching any one of these methods worth the effort."

---

## Description

"Windows Threat Detection 3" closes out the series that started with Initial Access detection in room one and Discovery, Collection, and Ingress Tool Transfer in room two. This room picks up once the attacker is comfortable: the front door worked, and now they need a way back in that survives a reboot, a password reset, or the victim simply closing the RDP window. The room covers three MITRE ATT&CK tactics: Command and Control (TA0011), Persistence (TA0003), and Impact (TA0040).

The investigation runs across two evidence files (`Sysmon.evtx` and `Security.evtx`) for the Command and Control and account-backdoor sections, then hands off to a live lab VM for two more practice tasks where four separate malware samples, named Nessie, Troy, Odin, and Kitten, are already sitting on disk waiting to be found and executed. Every answer and flag below matches what I confirmed on the platform.

## The problem

Getting a shell on a machine and keeping that shell alive are two different problems. A threat actor who breaches a host over RDP can type commands directly into that session, but the moment the connection drops, gets closed, or the credential gets rotated, that access is gone. Most attackers do not gamble on the session staying open, so they build a second channel almost immediately: a Command and Control (C2) connection, meaning a process on the victim machine that phones home to attacker-controlled infrastructure and waits for instructions.

C2 traffic survives by hiding in plain sight. Rather than inventing a new protocol that firewalls would flag instantly, most C2 frameworks ride on protocols every network already allows: HTTP, HTTPS, DNS. MITRE catalogs this under Application Layer Protocol (T1071), and the logic is simple. A DNS query or an HTTPS request to an unfamiliar domain looks identical, at the packet level, to a browser checking for a software update. The only way to catch it is to know what "normal" looks like for a given host and notice when a background process starts talking to somewhere it has no business reaching.

Persistence solves a related but separate problem. Once an attacker has a C2 channel, they still need it to keep working after the host reboots, sometimes for a data stealer that grabs what it wants in minutes, but far more often for attacks that need to live inside a network for days, weeks, or longer. Windows offers dozens of documented ways to survive a reboot, but four of them account for the overwhelming majority of real intrusions: backdooring or hijacking a user account, creating a malicious service, creating a scheduled task, and planting an entry in a registry Run key or the Startup folder. This room walks through all four, plus the C2 setup that usually comes first.

## How it works

**Step 1: Spot the C2 channel.** Evidence file: `C:\Users\Administrator\Desktop\Practice\Task 2\Sysmon.evtx`. The scenario opens with a phishing-style download rather than a network compromise, which fits how most C2 channels actually get their start.

| What happened | How it was found | Answer |
|---|---|---|
| User downloads a malicious archive | Filter Sysmon Event ID `11` (FileCreate), look for a browser process writing a `.zip` into Downloads | `URGENT!.zip` |
| Malware drops the real payload | Same Event ID `11` filter, trace the process tree after extraction | `C:\Users\Administrator\AppData\Roaming\update.exe` |
| Payload calls home | Filter Sysmon Event ID `22` (DNSEvent), match the `QueryName` to `update.exe`'s process | `route.m365officesync.workers.dev` |

Two design choices in this chain are worth slowing down on. First, the archive name plays on urgency, a filename built to make someone open it without thinking, which is a phishing pattern independent of whatever payload sits inside. Second, the dropped file lands in `AppData\Roaming` and calls itself `update.exe`. Neither location nor filename is inherently suspicious. Windows and half the software on a typical machine write to `AppData` constantly, and "update.exe" is a name every user has seen before, which is the disguise's entire goal. MITRE tracks this naming and placement trick as Masquerading (T1036), where the file stays fully visible but dressed up as something boring.

The domain is the most telling artifact. `route.m365officesync.workers.dev` borrows Microsoft 365 branding in its subdomain and runs on `workers.dev`, the domain Cloudflare Workers uses for serverless code executed at the network edge. Security researchers have tracked a sharp rise in abuse of Cloudflare's developer domains, with one 2024 analysis from Fortra measuring a 100 to 250 percent increase in `pages.dev` and `workers.dev` abuse compared to the year before. The appeal for an attacker is straightforward: `workers.dev` traffic gets valid TLS automatically, resolves through Cloudflare's reputable infrastructure, and most URL categorization engines rate it as benign by default, so a callback to that domain often sails past filters that would catch a freshly registered lookalike domain. This fits the Application Layer Protocol technique (T1071.001, specifically the web protocols sub-technique): the malicious traffic is just an HTTPS request to a domain that looks legitimate on every surface check.

**Step 2: Trace the backdoored account.** Evidence file: `C:\Users\Administrator\Desktop\Practice\Task 3\Security.evtx`. This task swaps the phishing angle for a more direct one: brute-forcing RDP and then planting an account to use later.

| Question | Event ID used | What it shows | Answer |
|---|---|---|---|
| Failed logon attempts against Administrator | `4625` | Repeated authentication failures targeting one account | `6` |
| Backdoor account created after the successful login | `4720` | A new local user appearing right after a `4624` success on the same session | `support` |
| Group the new account was added to | `4732` | Membership change adding the account to a privileged local group | `Administrators` |

The room's own guidance matters more than the three answers individually: the account name itself carries almost no signal. "support" could belong to a real IT helpdesk account just as easily as an attacker's plant. Context is what distinguishes an attacker's account creation from a legitimate one: who created it, from what source IP and at what time, and what else that same login session did in the minutes around the creation event. Six failed logons followed immediately by a success, followed immediately by a new privileged account, is a pattern no legitimate admin workflow produces. MITRE maps the brute-force stage to Brute Force (T1110) feeding into Valid Accounts (T1078), the account creation to Create Account: Local Account (T1136.001), and the group membership change to Account Manipulation (T1098).

**Step 3: Find the service and the scheduled task.** Evidence folder: `C:\Users\Administrator\Desktop\Practice\Task 4\`. The scenario states that the attackers planted two backdoors here, and the room wants both found before the system reboots and brings them to life.

| Persistence method | Malware | Detection path | Answer |
|---|---|---|---|
| Windows Service | Nessie | Security Event ID `4697` or System Event ID `7045` (service installed), or Sysmon Event ID `1` for an `sc.exe create` launch | Service name: `Data Protection Service` |
| Scheduled Task | Troy | Security Event ID `4698` (scheduled task created), or Sysmon Event ID `1` for a `schtasks.exe /create` launch | Task name: `AmazonSync` |
| Running the malware | Troy | Navigate to the path referenced in the task's `CommandLine` and execute it | Flag: `THM{c2_is_on_schedule!}` |

Both persistence methods work through the same core idea: register something with Windows that gets launched automatically, then let the operating system do the work of surviving a reboot. They differ in privilege level and in the audit trail they leave behind. A service created via `sc.exe` runs with SYSTEM-level privileges by default and starts before any user logs in, which is why "Data Protection Service" is a smart disguise; it sounds like a background component tied to Windows Data Protection API, something an analyst might skim past. A scheduled task is easier to create, does not always need administrative rights depending on how it is configured, and "AmazonSync" leans on the same masquerading logic as `update.exe` earlier, borrowing the name of legitimate cloud-sync software that plenty of machines run.

One detection detail is worth knowing outside the room itself: Event ID `4697` requires the "Audit Security System Extension" audit policy to be enabled, while the Service Control Manager writes its System-log counterpart, `7045`, with no extra policy needed. An environment that only enabled default auditing can still catch service-based persistence through `7045` even if `4697` is silent. On the scheduled task side, a `ParentCommandLine` of `svchost.exe -k netsvcs -p -s Schedule` is the fingerprint of a task firing through the Task Scheduler service, which is useful for building a process-tree rule that does not depend on the task's name at all. This pattern shows up well beyond lab environments: Emotet has been observed naming its scheduled tasks after legitimate system services to blend in, and Ryuk ransomware has used tasks like "AppMgmt" to launch `cmd.exe` running the batch scripts that kick off encryption.

**Step 4: Find the Run key and Startup folder backdoors.** Evidence folder: `C:\Users\Administrator\Desktop\Practice\Task 5\`. Two more backdoors, this time targeting per-user autostart locations rather than system-wide ones.

| Persistence method | Malware | Detection path | Answer |
|---|---|---|---|
| Startup folder | Odin | Sysmon Event ID `1` (Process Create), check the process's `ParentImage` | Parent process: `C:\Windows\explorer.exe` |
| Startup folder | Odin | Locate and run the malware, read its console output | Last output line: `Done doing bad stuff!` |
| Registry Run key | Kitten | Sysmon Event ID `13` (RegistryEvent, value set) under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, or check directly with `regedit.exe` | Flag: `THM{persisting_in_basket!}` |

Both mechanisms are aimed at a single-user login rather than system boot, and neither needs administrative rights, which is exactly why they show up in commodity malware as often as they do. Copying a file into `%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` is something any user can do, and Sysmon Event ID `11` (FileCreate) catches the drop. Adding a value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` is equally accessible, and Sysmon Event ID `13` picks it up. The `explorer.exe` parent process on Odin is the tell that ties both methods together: programs launched from the Startup folder or a Run key execute in the context of `explorer.exe` at logon, so any process with that parent and no obvious reason to be there deserves a second look.

Picus Security documented a campaign in October 2025 involving malware tracked as CABINETRAT that created a Run key entry to launch `cmd.exe`, and a separate case from September 2025 involved a PowerShell script that copied a payload into `AppData` and dropped a shortcut into the Startup folder to launch an AdaptixC2 beacon. Both cases date to within the last year: proof this technique still works against current defenses.

**Step 5: Connect it to Impact.** The final task steps back from individual event IDs to ask why any of this matters.

| Question | Answer |
|---|---|
| Biggest threat to most corporate Windows networks | Ransomware |
| Best stage to detect and stop an attack | Initial Access |

That second answer is the thesis of the entire three-room series. Every technique covered here, from the `workers.dev` C2 callback through the four persistence methods, exists in the gap between Initial Access and Impact. The room's own framing lists three reasons attackers bother with persistence at all: folding the host into a botnet for further attacks, spying as part of a longer state-sponsored campaign, and using one machine as a foothold into a much larger network. Real incidents back up all three at a scale that is easy to underestimate from inside a lab environment.

On the espionage side, Dragos published a case study in 2025 documenting how the Chinese state-linked group tracked as Volt Typhoon (identified in this specific intrusion as VOLTZITE) sat inside a small Massachusetts electric utility's operational technology network for roughly 300 days before discovery, having gained access in February 2023 and going unnoticed until a security vendor started deployment work in November of that year. CISA's advisory on the group states the same actor has maintained access inside other pieces of US critical infrastructure for as long as five years in some environments. The utility in that case was small and not a headline target, which is itself the warning: attackers do not always start with the biggest network they can find.

On the ransomware side, Verizon's 2026 Data Breach Investigations Report puts ransomware in 48 percent of the breaches it analyzed, up from 44 percent the prior year, though 69 percent of victims chose not to pay and the median ransom payment fell to roughly $139,875. The same report found a 240 percent rise in attackers abusing legitimate remote management tools compared to a 27 percent decline in traditional backdoor and C2 malware, a reminder that the exact techniques in this room are one branch of a landscape that keeps shifting, even as the underlying goal of durable, undetected access stays constant. Verizon's analysis also found a roughly 95-day median window between an attacker first harvesting credentials and eventually deploying ransomware, which is a long runway for a defender who is watching the right event IDs.

McLaren Health Care, the hospital system this room names as its Impact example, is a concrete illustration of what happens when that runway gets missed twice. In July 2023, the ALPHV/BlackCat ransomware group breached its network and later published data affecting roughly 2.2 million people. Barely a year later, between mid-July and early August 2024, a second ransomware group tracked as INC Ransom gained access to the same organization's network and, according to the breach notification McLaren filed, exposed information on 743,131 patients, including names, Social Security numbers, and medical records. Two major ransomware incidents against the same hospital system inside two years is not a story about one unlucky organization; it is a story about how much damage accumulates when the techniques covered in this room, C2 setup and persistence, go unnoticed long enough to reach Impact.

## Why it matters

The value of this room is not memorizing that a service named "Data Protection Service" or a domain ending in `m365officesync.workers.dev` is malicious. Those specific artifacts belong to one lab scenario and will never appear again outside it. A small, fixed set of Windows mechanisms is what generalizes here, and an even smaller set of event IDs records every touch: `4625` and `4624` for logon activity, `4720` and `4732` for account changes, `4697`, `7045`, and `4698` for service and task creation, and Sysmon `1`, `11`, `13`, and `22` for process, file, registry, and DNS telemetry. Malware families change every campaign. The registry paths, the scheduler API, and the DNS resolver do not.

Put together with rooms one and two, this series maps a full intrusion lifecycle in miniature: get in, figure out where you are and what is valuable, take it or set up shop, and stay. A SOC Level 1 analyst who can walk that chain end to end, recognizing the fingerprints at each stage rather than pattern-matching on a specific malware name, is equipped to catch the next campaign that has never been publicly documented, not just the one this room happened to script.

## Key takeaways

- C2 channels increasingly ride on trusted infrastructure like Cloudflare Workers rather than obviously malicious domains, which means filename and folder choices (`update.exe` in `AppData\Roaming`) matter as much as the domain itself.
- A backdoored account gets caught by correlating account creation events with the login session and source that created them, not by a suspicious username.
- Services and scheduled tasks both survive reboot by registering with Windows rather than staying resident in memory, but they differ in privilege level and in which audit policy needs to be enabled to see them.
- Run keys and the Startup folder need no administrative rights at all, and both produce an `explorer.exe` parent process at logon, which is a reliable pivot point regardless of the malware's name.
- Ransomware remains the top threat to Windows networks, confirmed by both this room and Verizon's 2026 DBIR data, and the earlier in the kill chain a defender catches it, the smaller the eventual Impact.
- Specific IOCs like a domain name or malware filename expire within one campaign, so the event IDs and registry paths that catch them are the part worth remembering.