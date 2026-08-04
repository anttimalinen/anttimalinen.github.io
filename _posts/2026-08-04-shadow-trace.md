---

title: Shadow Trace

date: 2026-08-04 18:00 +0300

categories: [Foundations, Malware]

tags: [malware-analysis, ioc-extraction, static-analysis, dfir, threat-intelligence]

description: "A TryHackMe SOC Level 1 writeup on static file triage with PEStudio, decoding a base64-hidden flag, reading a socket import for capability, and correlating two EDR alerts back to the same binary to build one incident timeline."

---

## Description

"Shadow Trace" drops the analyst into a night shift with one manager phone call and no other context: a file called `windows-update.exe` sat on a user's desktop, and the EDR is now throwing alerts. The room is a capstone rather than a tutorial. It builds directly on Introduction to Malware Analysis and Malware Classification, both listed as prerequisites, and it expects the analyst to already know static analysis method and category recognition. Correlation is the piece it adds: proving that a suspicious binary and two separate EDR alerts describe the same incident, using nothing but a hex string, a socket import, and two decoding puzzles.

This post walks through the static analysis of `windows-update.exe` with PEStudio, extracting a URL and domain as indicators of compromise (IOC), decoding an embedded flag from a base64 string, reading a network import to establish capability, and then correlating a PowerShell alert and a Chrome alert back to the same file and the same infrastructure.

## The problem

A binary called `windows-update.exe` sitting on a desktop tells an analyst almost nothing on its own. Windows Update does not distribute itself as a standalone executable a user downloads and runs; it operates through a background service and the Microsoft Update Catalog, not a file a user finds sitting on their own desktop. The attacker's naming choice works anyway, because most people, and a fair number of security tools relying on filename or path allowlists, will not question it. This is Masquerading, MITRE ATT&CK T1036, sub-technique T1036.005, Match Legitimate Name or Location. Picus Security's Red Report 2026, built from over 1.1 million analyzed malware samples, ranks Masquerading sixth among the ten most prevalent techniques in the wild, present in 16.59 percent of attacks, and calls out renamed files like `update.exe` by name as the textbook example of an adversary hiding in plain sight.

The second half of the problem is worse than the first, and it's the one that costs SOC teams the most time. Even after an analyst confirms a file is suspicious, that confirmation sits in isolation unless it connects to what the rest of the environment is reporting. An EDR alert with a command line full of encoded text looks like noise on its own, one line in a queue an overloaded Tier 1 analyst might close as a false positive rather than dig into. A second alert from a browser process looks unrelated entirely, filed under a different alert type in a different part of the dashboard. The actual job in this room is not spotting that any one of these three things looks wrong. It's proving they're the same thing, so the response, isolate the host, block the domain, hunt for the same indicators elsewhere, targets the right infrastructure instead of one symptom of it.

## How it works

**Step 1: Setting the scene**

The room hands over one fact and one instruction: a file needs immediate review, and the analyst has DFIR (Digital Forensics and Incident Response) tools already staged on the lab machine. No sandbox detonation, no execution. The entire investigation runs through static analysis first: examining the file's structure, strings, and metadata without ever running it, which keeps the analysis machine safe and preserves whatever evidence the file's byte layout can offer before anything gets the chance to self-delete or evade a live environment.

This is a direct continuation of the method taught in Introduction to Malware Analysis, one of the room's listed prerequisites: static analysis comes first because it carries zero risk of infecting the host, and dynamic analysis (running the file in an isolated sandbox to observe its behavior) only gets used when static analysis runs out of answers. Malware Classification, the second prerequisite, supplies the other half of the mental model: before touching a single tool, an analyst already has a rough sense of what category a file like this is likely to fall into from the scenario alone. A file impersonating a system update, dropped on a single user's desktop rather than pushed through a management console, reads like a downloader or a first-stage loader rather than, say, a wiper or a keylogger, and that hypothesis shapes which indicators are worth chasing first.

**Step 2: Confirming architecture and identity with PEStudio**

PEStudio is a free, offline static analysis tool built for inspecting Windows PE (Portable Executable, the file format behind `.exe`, `.dll`, and `.sys` files) binaries without executing them. It presents the file's header, section table, imports, exports, and embedded strings in one interface, color-coding entries the tool judges suspicious so an analyst can triage a sample quickly instead of reading a hex dump line by line. Opening `windows-update.exe` in PEStudio and checking the Indicators tab under the file group answers the first two questions immediately: the binary is 64-bit, and its SHA-256 hash is `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc`.

| Field | Value | Why it matters |
|---|---|---|
| Architecture | 64-bit | Confirms compatibility and rules out a 32-bit-only detection rule missing it |
| SHA-256 hash | `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc` | A unique fingerprint for the exact file, usable to search VirusTotal, pivot in a SIEM, or add to a blocklist |

An analyst without PEStudio open can pull the same hash directly from PowerShell with `Get-FileHash C:\Users\DFIRUser\Desktop\windows-update.exe -Algorithm SHA256`, which is worth knowing since not every environment has a dedicated static analysis tool installed on every jump box. The hash becomes the anchor for the rest of the investigation: every IOC pulled afterward gets tied back to this exact file, not a vague description of a suspicious update executable.

The same Indicators tab also reports the file's entropy, a measure of how random the binary's contents look on a scale where higher values suggest packing or encryption designed to defeat static string extraction. `windows-update.exe` doesn't come back packed, which is good news for the rest of the investigation: it means the strings and imports examined in the next three steps are sitting in the file as plaintext rather than compressed or encrypted behind a packer stub an analyst would need to unwrap first. Not every sample cooperates this easily, which is part of why checking entropy before diving into strings is a standard first move rather than a step this room happens to skip.

**Step 3: Pulling IOCs from the strings table**

An IOC (Indicator of Compromise) is any artifact, a hash, an IP address, a domain, a URL, that signals malicious activity and can be searched for elsewhere in the environment. Every PE file carries a strings table full of raw text: library names, error messages, and, in a poorly hardened sample, whatever URLs, paths, and configuration values a developer left as literal text rather than building at runtime. Reading through that table by hand is what static analysis usually means in practice, and it's the step most likely to hand an analyst something immediately actionable. PEStudio's `strings` tab, filtered to the `url-pattern` row under Indicators, surfaces two hits inside `windows-update.exe`: an IP address and a URL. The URL is the one that matters here: `http://tryhatme.com/update/security-update.exe`.

Sorting the full strings list by size and scanning for repeated fragments of that domain turns up a second, more specific IOC: `responses.tryhatme.com`. This is a meaningfully different finding from the first URL. The delivery URL tells an analyst where the payload came from. The second domain, buried separately in the strings rather than sitting next to the delivery URL, reads like infrastructure the malware talks to after it runs, which is exactly the kind of detail that turns a single IOC into a pivot point for finding the rest of an attacker's infrastructure.

| IOC type | Example from this file | What an analyst does with it |
|---|---|---|
| Hash | `b2a88de3...64bfc` (SHA-256) | Search VirusTotal, add to an EDR blocklist, confirm identity across systems |
| URL | `http://tryhatme.com/update/security-update.exe` | Identify the delivery mechanism, block at the proxy or firewall |
| Domain | `responses.tryhatme.com` | Pivot to passive DNS or threat intel feeds to find related infrastructure |

Each IOC type answers a different question. A hash confirms this exact file and nothing else, since changing a single byte changes the hash entirely. A URL or domain generalizes further, since an attacker often reuses infrastructure across multiple payloads and campaigns, which is exactly why the domain recovered here becomes so important once the alert dashboard enters the picture.

**Step 4: Decoding the embedded flag**

Next to the `responses.tryhatme.com` string sits something that looks like noise: a block of characters ending in an equals sign, the classic padding character for base64. The specific string is `VEhNe3lvdV9nMHRfc29tZV9JT0NzX2ZyaWVuZH0=`. Base64 is an encoding, not encryption: it represents binary or text data using a fixed 64-character alphabet, and it reverses cleanly with no key required, which is exactly why it shows up constantly in both legitimate software and malware alike. Running that string through CyberChef's `From Base64` recipe, or letting CyberChef's `Magic` operation auto-detect the encoding, returns the flag: `THM{you_g0t_some_IOCs_friend}`.

The placement is the lesson here as much as the decoding step. An attacker embedding a base64 blob next to a C2 (Command and Control) domain inside a binary's strings is a common pattern for hiding a secondary payload URL, a configuration value, or an authentication token from casual string-scanning tools that only flag plaintext matches against known-bad domains. A string that looks like gibberish is exactly the string worth decoding first.

CyberChef, built by GCHQ and run entirely in the browser, earns its reputation as a DFIR staple because it chains these small decoding steps together instead of forcing an analyst to write a one-off script for every encoding scheme encountered. Base64, hex, URL encoding, decimal, and dozens of others all live in the same recipe list, and the Magic operation attempts to auto-detect which one applies when the encoding isn't obvious on sight. That flexibility matters here, since Step 7 below reuses the same tool against a different encoding scheme applied to a different alert.

**Step 5: Reading the import table for capability**

PEStudio's Libraries tab lists every DLL a binary imports, and each import is a promise about what the binary can do at runtime. `windows-update.exe` imports `WS2_32.dll`, the Winsock (Windows Sockets) library that provides Berkeley-compatible socket functions for raw TCP and UDP communication. This detail matters because Windows offers multiple distinct APIs for network activity, and the one a binary imports tells an analyst roughly what kind of traffic to expect on the wire before a single packet is captured.

| Networking API | Library | Typical use |
|---|---|---|
| Winsock (Sockets) | `WS2_32.dll` | Raw, session-level TCP or UDP access, common in custom C2 clients and downloaders |
| WinInet | `wininet.dll` | Higher-level HTTP requests, similar to how a browser fetches a page |
| URLMon | `urlmon.dll` | URL monikers and download helpers, often used for simple file-fetch operations |

`windows-update.exe` sits in the first row. Malware that imports `WS2_32.dll` is set up to open its own raw connections rather than relying on a browser-style HTTP wrapper, which is precisely the kind of low-level, self-contained network capability a first-stage downloader or C2 client needs, and it's a distinction reverse engineers have relied on for exactly this reason since long before this room existed.

Seeing this import next to the two domains recovered in Step 3 turns a static file into a working theory: this binary is built to reach out to network infrastructure on its own, and the strings already extracted are strong candidates for exactly where it reaches.

**Step 6: Correlating the PowerShell alert**

With the file itself fully characterized, the room shifts to the EDR alert dashboard. The first alert fires on `powershell.exe`, and its command field contains an `Invoke-Expression`-and-`DownloadString` chain wrapped around a `System.Text.Encoding` call decoding a base64 string, the fileless download-and-execute pattern (`IEX (New-Object Net.WebClient).DownloadString(...)` fed a `FromBase64String`-decoded argument). Decoding the embedded base64 in CyberChef returns `https://tryhatme.com/dev/main.exe`.

The domain matches. `tryhatme.com` is the same root domain recovered from the binary's strings in Step 3, now appearing as the live target of a PowerShell download command on an EDR alert. That's no longer two separate suspicious things. It's one campaign, observed at two different points: once frozen inside a file on disk, once caught executing live.

This pattern, PowerShell obfuscating a download URL inside a base64 blob rather than typing it in plaintext, maps to MITRE ATT&CK T1027.010, Command Obfuscation, layered with T1105, Ingress Tool Transfer, for the download itself. It's the same `IEX`-and-`DownloadString` fileless download-and-execute pattern covered in the Living Off the Land Attacks writeup on this blog, here wrapped in an extra layer of base64 rather than left in plaintext. It's a well-documented real-world pattern: Hive ransomware operators have used base64-obfuscated PowerShell payloads for exactly this purpose. PowerShell Script Block Logging (Windows Event ID 4104) exists because it captures the fully decoded command regardless of how many encoding layers wrap it, the same principle CyberChef applies manually in this room. A SOC that only alerts on the raw command line, without decoding the base64 payload first, sees a wall of characters instead of a URL, which is why the manual decoding step in this task matters as much as spotting the alert in the first place.

**Step 7: Correlating the Chrome alert**

The second alert fires on `chrome.exe`, and its command contains a `fetch()` call, but instead of a readable URL the argument is a run of numbers separated by colons. Feeding that numeric string into CyberChef, using Magic or a manual decimal-to-text conversion, resolves it to `https://reallysecureupdate.tryhatme.com/update.exe`. The same alert's command also specifies a `download=` parameter naming the file `test.txt`, meaning the fetch call is set to save its result locally under an innocuous filename rather than a `.exe` extension that would draw immediate attention from a user or a file-type filter.

Encoding a URL as a string of decimal numbers is a lightweight but genuinely used evasion pattern: it defeats simple plaintext pattern matching the same way base64 does, through a different alphabet, and researchers have documented full campaigns built around it. Menlo Security's research into "Legacy URL Reputation Evasion" catalogued weaponized documents using decimal-encoded and other camouflaged IP and URL formats to slip past content-inspection engines that scan for recognizable URL patterns, and a similar decimal-encoded redirect chain was tracked years earlier feeding into the RIG exploit kit and Smoke Loader malware. The mechanism in this alert, a numeric string a browser-side script decodes back into a live URL, sits in that same family of technique.

Two domains, `tryhatme.com` in the binary and the PowerShell alert, `reallysecureupdate.tryhatme.com` in the Chrome alert, share the same root, which is the second confirmation that every piece collected so far, the file, the PowerShell alert, and the Chrome alert, traces back to one actor's infrastructure rather than three unrelated events sharing a SOC queue by coincidence.

**Step 8: Building the case**

Laid end to end, the investigation produces a single timeline instead of three disconnected findings.

| Source | Finding | Ties back to |
|---|---|---|
| Static file (`windows-update.exe`) | Delivery URL `http://tryhatme.com/update/security-update.exe`, C2 domain `responses.tryhatme.com`, `WS2_32.dll` import | Root domain `tryhatme.com` |
| PowerShell alert | Base64-obfuscated download of `https://tryhatme.com/dev/main.exe` | Same root domain, live execution |
| Chrome alert | Decimal-encoded fetch of `https://reallysecureupdate.tryhatme.com/update.exe`, saved as `test.txt` | Subdomain of the same root domain |

A file masquerading as a Windows Update executable carries a delivery URL and a secondary domain in its strings, plus a Winsock import confirming it's built to talk to the network directly. A PowerShell alert shows that same root domain being used live to pull a second-stage payload, hidden behind base64 the way T1027.010 predicts. A Chrome alert shows a subdomain of the same root domain being reached through decimal-encoded obfuscation, dropping a file under a deliberately boring name. None of these three findings alone justifies a full incident response. Together, they describe one campaign using one piece of shared infrastructure across three different vectors, which is exactly the threshold that should trigger isolating the host, hunting for `tryhatme.com` and its subdomains across the rest of the environment, and treating the SHA-256 hash from Step 2 as a blocklist entry rather than a curiosity.

**Step 9: From investigation to response**

Building the case is not the last step in a real SOC, even though the room's flag arrives at Step 8. Once an analyst has a consolidated IOC set like the table above, the next actions are procedural rather than technical. The hash, both URLs, and both domains get submitted to whatever platform the organization uses to share threat intelligence internally, commonly something built on the STIX (Structured Threat Information eXpression) and TAXII (Trusted Automated Exchange of Intelligence Information) standards or an open-source platform like MISP, so that every other team, email security, network detection, endpoint protection, can search for and block the same indicators without repeating the analysis from scratch. The host itself gets isolated rather than cleaned in place, since a machine that already ran a PowerShell download and a browser-side fetch may have follow-on payloads an analyst hasn't found yet. And the finding gets written up in plain language for whoever owns incident response next: what the file was, what it did, what domains it touched, and what evidence supports each claim.

This is the "basic SOC triage" the room's learning objectives name directly. Extracting IOCs and correlating alerts are the technical middle of the job. Turning that work into a decision, isolate this host, block this domain, hunt for this hash elsewhere, is the actual point of doing it.

## Why it matters

Every technique in this room shows up in real telemetry, not only in lab scenarios. Masquerading a payload as an update executable is common enough that Picus Security's Red Report 2026 names `update.exe` as an illustrative example while ranking the broader Masquerading technique sixth out of the ten most prevalent behaviors across more than a million analyzed malware samples from 2025. The report's wider finding, that 80 percent of the top ten techniques observed last year serve evasion, persistence, or stealthy command and control rather than smash-and-grab impact, is the same shift this room is built to train against: the analyst's job increasingly means noticing what's hiding in plain sight rather than what's plainly broken.

The obfuscation layered into both alerts follows the same real-world logic. Base64-wrapped PowerShell download commands, the pattern behind the `tryhatme.com` PowerShell alert, have been documented in Hive ransomware intrusions and in QakBot's HTML smuggling campaigns, where a base64-encoded JavaScript payload sat inside an email attachment's hyperlink to slip past content filters that only inspect plaintext. Decimal-encoded URLs, the pattern behind the Chrome alert, trace back through documented campaigns including a historical redirect chain feeding the RIG exploit kit and Smoke Loader, and more recent research into camouflaged template-injection URLs designed to defeat file-based content inspection. Neither technique is exotic. Both are inexpensive enough that a wide range of financially motivated operators reach for them by default.

Reading a socket import as a capability signal, the move made in Step 5, is not a room-specific trick. Mandiant's own reverse engineering research splits Windows malware command-and-control communication into the same handful of API categories used here, sockets, WinInet, URLMon, and COM, precisely because the choice of API is one of the first things a reverse engineer checks when building a network-based detection signature. Sikorski and Honig's "Practical Malware Analysis," a standard reference in the field, opens its networking chapter with the same observation: Berkeley-compatible sockets through `WS2_32.dll` are the most common Windows networking mechanism malware relies on, which is exactly the import this room hands an analyst as the clue that ties the file's capability to the traffic pattern later confirmed by the alerts.

The larger lesson is about correlation as a distinct skill from either static analysis or alert triage on their own. An analyst who can extract a hash, a URL, and a domain from a binary, and separately read two EDR alerts, has done half the job. Recognizing that `tryhatme.com` connects all three, and that the connection is the actual finding worth escalating, is what separates a Tier 1 analyst clearing a queue from a Tier 2 analyst building a case an incident response team can act on.

That distinction is why Shadow Trace sits where it does in the SOC Level 1 path, after the analyst already knows static analysis method from Introduction to Malware Analysis and category recognition from Malware Classification. Neither prerequisite room asks for correlation across multiple evidence sources in a single exercise. This one does, and it does it with the same tools, PEStudio and CyberChef, an analyst already learned to trust, applied to a puzzle that only resolves once every piece is on the table at the same time.

## Key takeaways

- Static analysis with a tool like PEStudio extracts architecture, hash, strings, and imports from a suspicious binary without ever executing it, which is the safe default for any unknown file.
- A binary named to mimic legitimate software, such as `windows-update.exe`, is MITRE ATT&CK T1036.005, Masquerading: Match Legitimate Name or Location, a technique the Red Report 2026 places among the ten most common in the wild.
- IOCs (Indicators of Compromise) like hashes, URLs, and domains only become useful once they're extracted and searchable; a hash pulled in Step 2 becomes a blocklist entry, and a domain pulled from strings becomes the thread that ties every later alert together.
- Base64 encoding data inside a binary or a command line, MITRE ATT&CK T1027.010, Command Obfuscation, is reversible without a key and defeats plaintext string matching, which is exactly why CyberChef's `From Base64` and `Magic` operations exist as standard DFIR tooling.
- The choice of networking API a binary imports, Winsock via `WS2_32.dll` versus WinInet or URLMon, signals what kind of network traffic to expect before a single connection is observed.
- Decimal-encoded URLs are a documented real-world evasion technique, not a puzzle invented for this room; researchers have tracked full campaigns built around exactly this pattern.
- The actual skill this room tests is correlation: connecting a static file, a PowerShell alert, and a browser alert back to one shared domain, which turns three disconnected findings into a single, actionable incident.
- Extracting IOCs is only half the workflow; sharing them through a platform built on standards like STIX and TAXII, or an open-source option like MISP, and isolating the affected host, is what turns an analyst's findings into an organization-wide defense.